# 漏洞扫描报告 — 待确认漏洞

**项目**: MindSpeed-LLM
**扫描时间**: 2026-04-20T09:37:58.850Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| CONFIRMED | 31 | 81.6% |
| LIKELY | 7 | 18.4% |
| **总计** | **38** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 7 | 100.0% |
| **有效漏洞总计** | **7** | - |
| 误报 (FALSE_POSITIVE) | 0 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SEC-EXEC-001]** code_injection (High) - `mindspeed_llm/tasks/evaluation/eval_utils/human_utils.py:87` @ `unsafe_execute` | 置信度: 65
2. **[VULN-017]** Improper Neutralization of Directives in Dynamically Evaluated Code (High) - `mindspeed_llm/tasks/evaluation/eval_utils/human_utils.py:87` @ `unsafe_execute` | 置信度: 65
3. **[VULN-019]** Out-of-bounds Write (High) - `mindspeed_llm/fsdp2/data/megatron_data/helpers.cpp:33` @ `build_exhaustive_blending_indices` | 置信度: 60
4. **[VULN-020]** Out-of-bounds Write (High) - `mindspeed_llm/fsdp2/data/megatron_data/helpers.cpp:102` @ `build_blending_indices` | 置信度: 60
5. **[VULN-021]** Out-of-bounds Read (High) - `mindspeed_llm/fsdp2/data/megatron_data/helpers.cpp:196` @ `build_sample_idx` | 置信度: 60
6. **[VULN-023]** Out-of-bounds Read (High) - `mindspeed_llm/fsdp2/data/megatron_data/helpers.cpp:398` @ `build_mapping_impl` | 置信度: 60
7. **[VULN-026]** Out-of-bounds Read (High) - `mindspeed_llm/fsdp2/data/megatron_data/helpers.cpp:659` @ `build_blocks_mapping_impl` | 置信度: 60

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `undefined@undefined` | training | - | - | GPT model pretraining entry point |
| `undefined@undefined` | evaluation | - | - | Model evaluation entry point for various benchmarks |
| `undefined@undefined` | inference | - | - | Model inference entry point |
| `undefined@undefined` | data_preprocessing | - | - | Data preprocessing for training |
| `undefined@undefined` | checkpoint_conversion | - | - | Checkpoint format conversion |
| `undefined@undefined` | rlhf_training | - | - | RLHF (Reinforcement Learning from Human Feedback) training |


---

## 3. High 漏洞 (7)

### [VULN-SEC-EXEC-001] code_injection - unsafe_execute

**严重性**: High | **CWE**: CWE-94 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `mindspeed_llm/tasks/evaluation/eval_utils/human_utils.py:87-88` @ `unsafe_execute`
**模块**: evaluation

**描述**: exec() 执行模型生成的代码用于 HumanEval 测试。虽然 reliability_guard() 提供了有限的保护（注释明确说明这不是真正的安全沙箱），但模型生成的代码可能执行恶意操作。代码内容来自模型推理输出。

**漏洞代码** (`mindspeed_llm/tasks/evaluation/eval_utils/human_utils.py:87-88`)

```c
exec(check_program, exec_globals)
```

**达成路径**

模型输出 completion + problem['prompt'] + problem['test'] -> check_program -> exec(check_program) [SINK]

**验证说明**: exec() on model-generated code, reliability_guard provides limited protection but explicitly states NOT a security sandbox.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-017] Improper Neutralization of Directives in Dynamically Evaluated Code - unsafe_execute

**严重性**: High | **CWE**: CWE-95 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow_scanner

**位置**: `mindspeed_llm/tasks/evaluation/eval_utils/human_utils.py:87` @ `unsafe_execute`
**模块**: mindspeed_llm/tasks/evaluation

**描述**: exec() executes model-generated code for HumanEval benchmark. reliability_guard() provides limited protection but is NOT a real security sandbox.

**漏洞代码** (`mindspeed_llm/tasks/evaluation/eval_utils/human_utils.py:87`)

```c
exec(check_program, exec_globals)
```

**达成路径**

problem[prompt] + completion + problem[test] → check_program → exec()

**验证说明**: exec() executes model-generated code. reliability_guard disabled dangerous functions but explicitly noted NOT a real sandbox.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-019] Out-of-bounds Write - build_exhaustive_blending_indices

**严重性**: High | **CWE**: CWE-787 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow_scanner

**位置**: `mindspeed_llm/fsdp2/data/megatron_data/helpers.cpp:33-62` @ `build_exhaustive_blending_indices`
**模块**: mindspeed_llm/fsdp2/data/megatron_data

**描述**: Unchecked array bounds in build_exhaustive_blending_indices. num_datasets not validated against sizes array length; output arrays not validated against required size.

**漏洞代码** (`mindspeed_llm/fsdp2/data/megatron_data/helpers.cpp:33-62`)

```c
for (int32_t i = 0; i < num_datasets; ++i) { total_size += sizes_ptr[i]; } // OOB if i >= sizes.shape(0)
```

**达成路径**

Python caller → sizes array + num_datasets → unchecked array access

**验证说明**: C++ array bounds not fully validated, but pybind11 numpy interface provides some implicit checks.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-020] Out-of-bounds Write - build_blending_indices

**严重性**: High | **CWE**: CWE-787 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow_scanner

**位置**: `mindspeed_llm/fsdp2/data/megatron_data/helpers.cpp:102-123` @ `build_blending_indices`
**模块**: mindspeed_llm/fsdp2/data/megatron_data

**描述**: build_blending_indices writes to output arrays for size iterations without bounds validation.

**漏洞代码** (`mindspeed_llm/fsdp2/data/megatron_data/helpers.cpp:102-123`)

```c
for (int64_t sample_idx = 0; sample_idx < size; ++sample_idx) { dataset_index_ptr[sample_idx] = ...; }
```

**达成路径**

Python caller → output arrays + size parameter → unchecked write

**验证说明**: C++ array bounds unvalidated, pybind11 has implicit checks

---

### [VULN-021] Out-of-bounds Read - build_sample_idx

**严重性**: High | **CWE**: CWE-125 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow_scanner

**位置**: `mindspeed_llm/fsdp2/data/megatron_data/helpers.cpp:196-197` @ `build_sample_idx`
**模块**: mindspeed_llm/fsdp2/data/megatron_data

**描述**: build_sample_idx reads from sizes array using indices from document_idx without bounds validation.

**漏洞代码** (`mindspeed_llm/fsdp2/data/megatron_data/helpers.cpp:196-197`)

```c
auto document_index = document_idx[document_idx_index]; auto document_length = sizes[document_index];
```

**达成路径**

document_idx values → used as indices into sizes → OOB read if invalid

**验证说明**: C++ array OOB read, pybind11 has implicit checks

---

### [VULN-023] Out-of-bounds Read - build_mapping_impl

**严重性**: High | **CWE**: CWE-125 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow_scanner

**位置**: `mindspeed_llm/fsdp2/data/megatron_data/helpers.cpp:398` @ `build_mapping_impl`
**模块**: mindspeed_llm/fsdp2/data/megatron_data

**描述**: build_mapping_impl reads from sizes array using sent_index from docs array without bounds validation.

**漏洞代码** (`mindspeed_llm/fsdp2/data/megatron_data/helpers.cpp:398`)

```c
if (sizes[sent_index] > LONG_SENTENCE_LEN) { ... }
```

**达成路径**

docs[doc] → sent_index → sizes[sent_index] → OOB if sent_index >= sizes.shape(0)

**验证说明**: C++ array OOB read, pybind11 has implicit checks

---

### [VULN-026] Out-of-bounds Read - build_blocks_mapping_impl

**严重性**: High | **CWE**: CWE-125 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow_scanner

**位置**: `mindspeed_llm/fsdp2/data/megatron_data/helpers.cpp:659-689` @ `build_blocks_mapping_impl`
**模块**: mindspeed_llm/fsdp2/data/megatron_data

**描述**: build_blocks_mapping_impl reads from sizes and titles_sizes using indices from docs without bounds validation.

**漏洞代码** (`mindspeed_llm/fsdp2/data/megatron_data/helpers.cpp:659-689`)

```c
const auto sent_index_first = docs[doc]; const auto target_seq_len = max_seq_length - titles_sizes[doc];
```

**达成路径**

docs values → used as indices → OOB read

**验证说明**: C++ array OOB read, pybind11 has implicit checks

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| evaluation | 0 | 1 | 0 | 0 | 1 |
| mindspeed_llm/fsdp2/data/megatron_data | 0 | 5 | 0 | 0 | 5 |
| mindspeed_llm/tasks/evaluation | 0 | 1 | 0 | 0 | 1 |
| **合计** | **0** | **7** | **0** | **0** | **7** |

## 5. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-125 | 3 | 42.9% |
| CWE-787 | 2 | 28.6% |
| CWE-95 | 1 | 14.3% |
| CWE-94 | 1 | 14.3% |
