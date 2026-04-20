# 漏洞扫描报告 — 已确认漏洞

**项目**: MindSpeed
**扫描时间**: 2025-04-20T01:15:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次安全扫描针对华为昇腾 NPU 大模型加速库 MindSpeed（960 个文件，包含 911 个 Python 文件和 49 个 C/C++ 文件）进行了深度漏洞分析，共发现 **12 个已确认漏洞**，其中 4 个 Critical 级别、6 个 High 级别、1 个 Medium 级别。

**关键风险发现**：MindSpeed 的 checkpoint 加载机制存在严重的反序列化漏洞集群。核心问题是多个模块使用 `torch.load()` 加载外部 checkpoint 文件时未设置 `weights_only=True` 参数，允许攻击者通过恶意 pickle payload 执行任意代码。该漏洞影响 checkpointing、layerzero、tools 等多个关键模块，覆盖了模型加载、分布式训练、数据预处理等核心功能路径。

**业务影响**：在大模型训练场景中，研究人员经常从 HuggingFace Hub、ModelScope 等平台下载预训练模型 checkpoint。如果攻击者在模型分发渠道植入恶意 checkpoint，用户加载时将触发任意代码执行，可能导致：
- 训练数据泄露（包含敏感训练样本）
- 模型权重被篡改（植入后门）
- 系统被完全控制（横向移动、权限提升）

**修复优先级**：建议立即在所有 `torch.load()` 调用中添加 `weights_only=True` 参数，同时实施 checkpoint 来源白名单和完整性校验机制。对于 LayerZero 配置中的路径验证逻辑需要重构，当前仅验证路径是否为绝对路径，无法提供有效防护。

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
| Critical | 4 | 33.3% |
| High | 6 | 50.0% |
| Medium | 1 | 8.3% |
| **有效漏洞总计** | **12** | - |
| 误报 (FALSE_POSITIVE) | 38 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-PY-CHKPT-001]** deserialization (Critical) - `mindspeed/checkpointing.py:277` @ `_load_base_checkpoint` | 置信度: 95
2. **[VULN-CROSS-TORCH-LOAD-001]** deserialization (Critical) - `mindspeed/checkpointing.py + mindspeed/core/distributed/layerzero/state/mga_checkpoint.py:277` @ `_load_base_checkpoint + load_layerzero_checkpoint` | 置信度: 95
3. **[VULN-CROSS-CHKPT-001]** deserialization_chain (Critical) - `mindspeed/checkpointing.py:277` @ `_load_base_checkpoint` | 置信度: 92
4. **[layerzero-mga_checkpoint-torch_load-188]** deserialization (Critical) - `mindspeed/core/distributed/layerzero/state/mga_checkpoint.py:188` @ `load_layerzero_checkpoint` | 置信度: 90
5. **[VULN-SEC-LZ-002]** deserialization (High) - `mindspeed/core/distributed/layerzero/state/scripts/layerzero_checkpointer.py:55` @ `ShardStateDict._init_metadata` | 置信度: 85
6. **[VULN-SEC-LZ-003]** deserialization (High) - `mindspeed/core/distributed/layerzero/state/scripts/layerzero_checkpointer.py:110` @ `LayerzeroCheckpoint._build_global_state` | 置信度: 85
7. **[VULN-SEC-PA-010]** race_condition (High) - `mindspeed/ops/csrc/pluggable_allocator/smart_swap/NPUSwapManager.cpp:952` @ `NPUSwapManager::Init/NPUSwapManager::DeInit` | 置信度: 85
8. **[VULN-tools-load_dataset-001]** Arbitrary Parameter Injection (High) - `tools/data_handler.py:510` @ `build_dataset` | 置信度: 85
9. **[VULN-tools-load_dataset-003]** Python Script Execution (High) - `tools/data_handler.py:518` @ `build_dataset` | 置信度: 85
10. **[VULN-CROSS-TOOLS-DATA-LOAD-001]** untrusted_data_loading (High) - `tools/preprocess_data.py + tools/data_handler.py:157` @ `main + build_dataset` | 置信度: 85

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

## 3. Critical 漏洞 (4)

### [VULN-DF-PY-CHKPT-001] deserialization - _load_base_checkpoint

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `mindspeed/checkpointing.py:277-284` @ `_load_base_checkpoint`
**模块**: checkpointing

**描述**: Unsafe torch.load deserialization without weights_only=True. The checkpoint file path is derived from load_dir parameter (semi-trusted file input) and passed through get_checkpoint_name() to torch.load(). PyTorch pickle-based deserialization allows arbitrary code execution when loading malicious checkpoint files.

**漏洞代码** (`mindspeed/checkpointing.py:277-284`)

```c
Line 277: state_dict = torch.load(checkpoint_name, map_location='cpu')
Line 284: ema_state_dict = torch.load(checkpoint_name + ".ema", map_location='cpu')
Line 310: state_dict = torch.load(checkpoint_name, map_location='cpu')
```

**达成路径**

Source: load_dir@mindspeed/checkpointing.py:204 (function parameter, semi_trusted) -> get_checkpoint_name() -> checkpoint_name -> torch.load() sink. No weights_only=True mitigation found.

**验证说明**: CONFIRMED deserialization vulnerability with multiple unsafe torch.load calls (lines 277, 284, 310). All calls lack weights_only=True. checkpoint_name derived from user-controlled load_dir parameter. Semi-trusted checkpoint input path with no validation. Critical risk for arbitrary code execution via malicious checkpoint files.

**评分明细**: base: 50 | reachability: 30 | controllability: 25 | mitigations: 0 | context: -10 | cross_file: 0

**深度分析**

**根因分析**: PyTorch 的 `torch.load()` 函数内部使用 Python `pickle` 模块进行反序列化。当不设置 `weights_only=True` 时，pickle 会还原任意 Python 对象，包括携带恶意代码的对象。MindSpeed 在三处 checkpoint 加载点均未使用此安全参数，形成了完整的攻击链。

**潜在利用场景**:
1. **恶意模型分发**: 攻击者在 HuggingFace Hub 发布带恶意 payload 的预训练模型，用户下载并加载后触发代码执行
2. **供应链攻击**: 攻击者篡改共享存储中的 checkpoint 文件，训练任务加载时被入侵
3. **内部威胁**: 恶意员工在 checkpoint 目录植入 payload，影响所有加载该 checkpoint 的训练任务

**修复建议**:
```python
# 立即修复：添加 weights_only=True
state_dict = torch.load(checkpoint_name, map_location='cpu', weights_only=True)
ema_state_dict = torch.load(checkpoint_name + ".ema", map_location='cpu', weights_only=True)
```
如果 checkpoint 包含非 tensor 数据（如 args、optimizer state），建议采用分层加载策略：仅用 `weights_only=True` 加载权重，其他元数据使用 JSON/YAML 存储。

---

### [VULN-CROSS-TORCH-LOAD-001] deserialization - _load_base_checkpoint + load_layerzero_checkpoint

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `mindspeed/checkpointing.py + mindspeed/core/distributed/layerzero/state/mga_checkpoint.py:277-188` @ `_load_base_checkpoint + load_layerzero_checkpoint`
**模块**: cross_module
**跨模块**: checkpointing → layerzero

**描述**: 跨模块反序列化漏洞集群: checkpointing 和 layerzero 模块共享相同的 torch.load 不安全调用模式。两个模块都从用户控制的 checkpoint 目录加载模型状态，未设置 weights_only=True 参数，允许通过恶意 pickle payload 执行任意代码。

**漏洞代码** (`mindspeed/checkpointing.py + mindspeed/core/distributed/layerzero/state/mga_checkpoint.py:277-188`)

```c
torch.load(checkpoint_name) [checkpointing.py:277]
torch.load(sd_file) [mga_checkpoint.py:188]
```

**达成路径**

[checkpointing] args.load_dir → torch.load
[layerzero] ckpt_dir → torch.load
共享 sink: torch.load 反序列化

**验证说明**: 调用链完整验证: checkpointing.py和layerzero/mga_checkpoint.py均使用torch.load无weights_only=True。路径来源于CLI参数(args.load_dir/ckpt_dir)，存在文件存在检查但无安全验证。攻击者可构造恶意checkpoint文件触发任意代码执行。

**评分明细**: base: 50 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**: 这是一个跨模块漏洞集群，checkpointing 和 layerzero 模块共享相同的不安全模式。代码库中存在 8 处 `torch.load()` 调用均未设置 `weights_only=True`，形成多点攻击面。值得注意的是，代码库已有安全实现参考（`mindspeed/mindspore/third_party/transformers/modeling_utils.py` 中使用 `weights_only=True`），但核心 checkpoint 加载代码未采纳。

**攻击向量分析**:
| 入口点 | 触发条件 | 风险等级 |
|--------|----------|----------|
| CLI `--load` 参数 | 用户指定恶意 checkpoint 目录 | Critical |
| LayerZero YAML 配置 `ckpt_load_path` | 配置文件指向恶意目录 | Critical |
| `convert_to_megatron.py --input-folder` | 转换工具加载恶意 checkpoint | High |

**修复建议**: 需在以下 8 个位置添加 `weights_only=True`：
- `checkpointing.py`: 行 277、284、310
- `mga_checkpoint.py`: 行 188
- `layerzero_checkpointer.py`: 行 55、110、127、135

同时建议引入 safetensors 格式作为替代方案，该格式不支持任意代码执行。

---

### [VULN-CROSS-CHKPT-001] deserialization_chain - _load_base_checkpoint

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 92/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `mindspeed/checkpointing.py:277-310` @ `_load_base_checkpoint`
**模块**: cross_module
**跨模块**: checkpointing → layerzero → config → scripts

**描述**: torch.load 反序列化跨模块链：checkpointing.py、layerzero/mga_checkpoint.py、layerzero/scripts/layerzero_checkpointer.py 均调用 torch.load 加载外部 checkpoint 文件，均未设置 weights_only=True。攻击者可通过构造恶意 checkpoint 文件在任一加载点触发任意代码执行。验证逻辑分散在 config.py（绝对路径检查）和 layerzero_checkpointer.py（前缀检查），但验证点与漏洞点分离，防御不完整。

**漏洞代码** (`mindspeed/checkpointing.py:277-310`)

```c
state_dict = torch.load(checkpoint_name, map_location='cpu')
ema_state_dict = torch.load(checkpoint_name + '.ema', map_location='cpu')
```

**达成路径**

args.load (CLI) → checkpointing.py → torch.load OR config.ckpt_load_path → layerzero/mga_checkpoint.py → torch.load OR convert_to_megatron.py --input-folder → layerzero_checkpointer.py → torch.load

**验证说明**: 跨模块torch.load反序列化链验证通过。三个入口点均可触发漏洞：(1)args.load → checkpointing.py:277/310 (2)config.ckpt_load_path → mga_checkpoint.py:188 (3)convert_to_megatron.py → layerzero_checkpointer.py。分散的验证逻辑无法提供完整防御。

**评分明细**: base: 50 | reachability: 30 | controllability: 12 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**防御失效根因**: 此漏洞揭示了 MindSpeed checkpoint 加载机制的 **防御纵深失效**。代码在 `config.py:266-270` 实施了路径验证（检查是否为绝对路径），但该验证：
1. **位置错误**: 验证点距离实际漏洞点（torch.load）跨越多个函数调用
2. **内容无效**: 仅验证路径格式，未验证路径来源或文件完整性
3. **覆盖不全**: 多个入口点（CLI、转换工具）完全跳过此验证

**攻击场景**: 攻击者可在 `/tmp/evil_checkpoint/model_0.pt` 创建恶意 checkpoint（绝对路径通过验证），配置 YAML 中设置 `ckpt_load_path: "/tmp/evil_checkpoint"`，验证通过后代码执行。

**修复建议**:
- Phase 1: 在所有 torch.load 调用点添加 `weights_only=True`
- Phase 2: 将验证移至实际加载点（point-of-use validation）
- Phase 3: 实施路径白名单（仅允许 `/data/checkpoints`、`/models/pretrained` 等受信任目录）

---

### [layerzero-mga_checkpoint-torch_load-188] deserialization - load_layerzero_checkpoint

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: python-dataflow-module-scanner, security-module-scanner

**位置**: `mindspeed/core/distributed/layerzero/state/mga_checkpoint.py:188` @ `load_layerzero_checkpoint`
**模块**: layerzero

**描述**: Unsafe torch.load call without weights_only=True. The ckpt_dir parameter is user-controlled and flows directly to torch.load, allowing arbitrary code execution via malicious pickle payloads in checkpoint files.

**漏洞代码** (`mindspeed/core/distributed/layerzero/state/mga_checkpoint.py:188`)

```c
state_dict = torch.load(sd_file)
```

**达成路径**

ckpt_dir -> sd_file (line 183) -> torch.load (line 188)

**验证说明**: CONFIRMED deserialization vulnerability. torch.load(sd_file) at line 188 lacks weights_only=True. The sd_file path is constructed from user-controlled ckpt_dir parameter, allowing arbitrary pickle deserialization. No sanitization or validation on checkpoint path. Full control over checkpoint directory enables malicious file placement.

**评分明细**: base: 50 | reachability: 30 | controllability: 25 | mitigations: 0 | context: -15 | cross_file: 0

**深度分析**

**技术挑战**: LayerZero checkpoint 包含复杂状态对象（args、optimizer state、RNG state、parallel_state），直接使用 `weights_only=True` 可能导致加载失败。但这不意味着可以放弃安全防护。

**现有缓解措施不足**:
- 绝对路径检查（`os.path.isabs()`）：仅验证格式，不验证安全
- 文件存在检查：仅验证路径有效，不验证内容可信
- 代码库官方文档已承认风险：`docs/zh/SECURITYNOTE.md` 明确提及 CVE-2025-32434

**分层修复方案**:
```python
# 短期：添加哈希校验和日志警告
import hashlib
def verify_checkpoint_hash(filepath, expected_hash):
    with open(filepath, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest() == expected_hash

# 中期：分离权重与元数据存储
# 权重使用 safetensors 格式（安全）
# args/iteration 等使用 JSON 存储
```

**长期**: 迁移至 safetensors + JSON 组合格式，彻底消除 pickle 反序列化风险。

---

### [VULN-SEC-LZ-002] deserialization - ShardStateDict._init_metadata

**严重性**: High | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-module-scanner, python-dataflow-module-scanner

**位置**: `mindspeed/core/distributed/layerzero/state/scripts/layerzero_checkpointer.py:55` @ `ShardStateDict._init_metadata`
**模块**: layerzero

**描述**: torch.load 反序列化用户提供的 checkpoint 文件名，无安全验证。filename 通过文件遍历传入，仅依赖前缀筛选，无法防止恶意文件被加载。

**漏洞代码** (`mindspeed/core/distributed/layerzero/state/scripts/layerzero_checkpointer.py:55`)

```c
state_dict = torch.load(self.filename, map_location='cpu')
```

**达成路径**

filename [属性] → torch.load(self.filename) [反序列化 Sink]

**验证说明**: CONFIRMED deserialization vulnerability. torch.load(self.filename) at line 55 lacks weights_only=True. filename flows from ShardStateDict constructor parameter, which receives files from user-controlled ckpt_dir via _get_files_by_key(). Weak mitigation: file prefix filter 'model_' allows attacker to name malicious file accordingly.

**评分明细**: base: 50 | reachability: 30 | controllability: 25 | mitigations: -5 | context: -15 | cross_file: 0

**深度分析**

**不充分缓解分析**: `_get_files_by_key()` 仅检查文件名前缀是否为 `"model_"`，这几乎无法阻止攻击：
- 攻击者只需将恶意文件命名为 `model_malicious.pt` 即可绕过
- 前缀检查不验证文件内容、来源、或完整性
- 遍历逻辑使用 `os.walk()`，会递归检查所有子目录

**入口点风险**: `convert_to_megatron.py` 通过 `--input-folder` 参数接受用户指定的 checkpoint 目录，该参数直接流向 `LayerzeroCheckpoint` 类，无任何中间验证。

**完整攻击链**:
```
用户输入 --input-folder=/tmp/attack/
    ↓
LayerzeroCheckpoint("/tmp/attack/")
    ↓
_get_files_by_key() → ["model_malicious.pt"] (前缀匹配通过)
    ↓
ShardStateDict("model_malicious.pt")
    ↓
torch.load() → 恶意 pickle payload 执行
```

**修复建议**:
1. 添加文件哈希白名单验证
2. 在 torch.load 添加 `weights_only=True`
3. 限制 checkpoint 目录权限（仅允许 owner 写入）
4. 添加审计日志记录所有 checkpoint 加载操作

---

## 4. High 漏洞 (6)

**严重性**: High | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-module-scanner, python-dataflow-module-scanner

**位置**: `mindspeed/core/distributed/layerzero/state/scripts/layerzero_checkpointer.py:110` @ `LayerzeroCheckpoint._build_global_state`
**模块**: layerzero
**跨模块**: layerzero → scripts

**描述**: torch.load 反序列化 checkpoint 文件列表首个文件，仅有文件名前缀检查（"model_"）缓解。前缀检查无法阻止攻击者在目标目录放置恶意文件。

**漏洞代码** (`mindspeed/core/distributed/layerzero/state/scripts/layerzero_checkpointer.py:110`)

```c
sd = torch.load(self.file_list[0], map_location=torch.device('cpu'))
```

**达成路径**

ckpt_dir [参数] → _get_files_by_key(ckpt_dir, "model_") [遍历+前缀筛选] → self.file_list[0] → torch.load [反序列化 Sink]

**验证说明**: CONFIRMED deserialization vulnerability. torch.load(self.file_list[0]) at line 110 lacks weights_only=True. file_list built from user-controlled ckpt_dir with weak prefix filter 'model_'. Attacker with control over checkpoint directory can place malicious pickle payload.

**评分明细**: base: 50 | reachability: 30 | controllability: 25 | mitigations: -5 | context: -15 | cross_file: 0

---

### [VULN-SEC-PA-010] race_condition - NPUSwapManager::Init/NPUSwapManager::DeInit

**严重性**: High（原评估: Medium → 验证后: High） | **CWE**: CWE-362 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-module-scanner

**位置**: `mindspeed/ops/csrc/pluggable_allocator/smart_swap/NPUSwapManager.cpp:952-1048` @ `NPUSwapManager::Init/NPUSwapManager::DeInit`
**模块**: pluggable_allocator
**跨模块**: torch_npu → pluggable_allocator

**描述**: NPUSwapManager 单例模式中的 Init/DeInit 函数缺乏线程同步保护（仅 isInit 标志检查）。多线程并发调用可能导致 executor/profiler 等成员被重复创建或提前删除，引发数据竞争和内存损坏。

**漏洞代码** (`mindspeed/ops/csrc/pluggable_allocator/smart_swap/NPUSwapManager.cpp:952-1048`)

```c
if (isInit) { return 0; }
// create executor, profiler, managers...
isInit = true;
```

**达成路径**

Thread A: isInit check -> create executor | Thread B: isInit check -> race -> memory corruption

**验证说明**: 真实漏洞！NPUSwapManager单例Init/DeInit仅用isInit标志检查，无锁/原子操作保护。多线程并发调用可导致executor/profiler被重复创建或提前删除，引发数据竞争和内存损坏。PyTorch多线程训练场景可直接触发。建议添加std::mutex或std::call_once。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-tools-load_dataset-001] Arbitrary Parameter Injection - build_dataset

**严重性**: High | **CWE**: CWE-88 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `tools/data_handler.py:510-513` @ `build_dataset`
**模块**: tools
**跨模块**: tools/preprocess_data.py,tools/data_handler.py

**描述**: Untrusted command-line argument --hf-datasets-params is loaded as JSON and passed directly to load_dataset(**param_dict) without validation. This allows attackers to inject arbitrary parameters including trust_remote_code=True, enabling potential remote code execution when loading malicious HuggingFace datasets.

**漏洞代码** (`tools/data_handler.py:510-513`)

```c
if args.hf_datasets_params:\n    with open(args.hf_datasets_params, 'r') as fin:\n        param_dict = json.load(fin)\n    return load_dataset(**param_dict)
```

**达成路径**

argv -> argparse.parse_args() -> args.hf_datasets_params -> json.load() -> load_dataset(**param_dict)

**验证说明**: 数据流完整验证：argv → args.hf_datasets_params → json.load() → load_dataset(**param_dict)。用户完全控制JSON文件内容，可注入任意参数如 trust_remote_code=True 触发远程代码执行。无任何输入验证或参数过滤。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-tools-load_dataset-003] Python Script Execution - build_dataset

**严重性**: High | **CWE**: CWE-94 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `tools/data_handler.py:518-526` @ `build_dataset`
**模块**: tools
**跨模块**: tools/preprocess_data.py,tools/data_handler.py

**描述**: Local Python scripts passed via --input are executed directly through load_dataset() without validation. The _has_py_script() function only checks if a .py file exists but does not validate the script content. Malicious dataset generation scripts could execute arbitrary code during dataset loading.

**漏洞代码** (`tools/data_handler.py:518-526`)

```c
if _has_py_script(args.input):\n    logger.info("loading data from a local python script")\n    raw_datasets = load_dataset(\n        args.input,\n        split=split_flag,\n        num_proc=None if args.streaming else args.workers,\n        cache_dir=cache_dir,\n        streaming=args.streaming\n    )
```

**达成路径**

argv -> argparse.parse_args() -> args.input -> _has_py_script() -> load_dataset(args.input)

**验证说明**: 数据流完整：argv → args.input → _has_py_script() → load_dataset(args.input)。_has_py_script()仅检查.py扩展名，无内容验证。用户可指定恶意Python脚本路径，实现任意代码执行。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-CROSS-TOOLS-DATA-LOAD-001] untrusted_data_loading - main + build_dataset

**严重性**: High | **CWE**: CWE-918 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `tools/preprocess_data.py + tools/data_handler.py:157-553` @ `main + build_dataset`
**模块**: cross_module
**跨模块**: tools → megatron.core.datasets

**描述**: tools 模块跨文件数据流: preprocess_data.py 的命令行参数流经 build_dataset() 到 data_handler.py 的 load_dataset() 调用点。用户控制的 --input 和 --hf-datasets-params 参数可直接触发远程数据加载或参数注入，信任边界跨越 CLI → 数据处理 → HuggingFace 下载。

**漏洞代码** (`tools/preprocess_data.py + tools/data_handler.py:157-553`)

```c
argv → args.input → build_dataset() → load_dataset(args.input) → remote data fetch
```

**达成路径**

[preprocess_data] argparse → args.input/args.hf_datasets_params
[data_handler] build_dataset → load_dataset(*param_dict) 或 load_dataset(args.input)

**验证说明**: 跨文件数据流验证通过。preprocess_data.py CLI参数直接传递到data_handler.py的load_dataset调用。--input和--hf-datasets-params参数可触发远程数据加载和参数注入(trust_remote_code=True)。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

## 5. Medium 漏洞 (1)

### [core-qos-env-type-confusion-20] type_confusion - __module__

**严重性**: Medium | **CWE**: CWE-704 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `mindspeed/core/qos/qos.py:20-26` @ `__module__`
**模块**: core

**描述**: Environment variables QOS_SDMA_* and QOS_ROCE_* are read using os.environ.get() with integer defaults. However, os.environ.get() returns a STRING when the environment variable exists, not the integer default. This creates type confusion: if QOS_SDMA_LOW=abc is set, it returns the string 'abc' instead of integer 2. This could cause TypeError in operations expecting integers, or silent comparison failures in QoS priority assignments.

**漏洞代码** (`mindspeed/core/qos/qos.py:20-26`)

```c
_DEFAULT_QOS_SDMA_LOW = os.environ.get('QOS_SDMA_LOW', 2)\n_DEFAULT_QOS_SDMA_MIDDLE = os.environ.get('QOS_SDMA_MIDDLE', 4)\n_DEFAULT_QOS_SDMA_HIGH = os.environ.get('QOS_SDMA_HIGH', 6)
```

**达成路径**

os.environ.get -> _DEFAULT_QOS_* (string or int) -> sdma_qos_str_to_value/roce_qos_str_to_value

**验证说明**: Genuine type confusion: os.environ.get() returns STRING when env var exists, no int() conversion or validation. Direct external input (env vars) allows attacker to inject non-integer values causing TypeError or silent comparison failures in QoS scheduling.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| checkpointing | 1 | 0 | 0 | 0 | 1 |
| core | 0 | 0 | 1 | 0 | 1 |
| cross_module | 2 | 1 | 0 | 0 | 3 |
| layerzero | 1 | 2 | 0 | 0 | 3 |
| ops-py | 0 | 0 | 0 | 0 | 0 |
| pluggable_allocator | 0 | 1 | 0 | 0 | 1 |
| tools | 0 | 2 | 0 | 0 | 2 |
| **合计** | **4** | **6** | **1** | **0** | **11** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-502 | 6 | 50.0% |
| N/A | 1 | 8.3% |
| CWE-94 | 1 | 8.3% |
| CWE-918 | 1 | 8.3% |
| CWE-88 | 1 | 8.3% |
| CWE-704 | 1 | 8.3% |
| CWE-362 | 1 | 8.3% |

---

## 8. 修复建议

### 优先级 1: 立即修复（Critical 漏洞）

**修复目标**: 消除所有 `torch.load()` 反序列化漏洞

| 位置 | 修复内容 | 影响范围 |
|------|----------|----------|
| `checkpointing.py:277` | 添加 `weights_only=True` | 主 checkpoint 加载 |
| `checkpointing.py:284` | 添加 `weights_only=True` | EMA checkpoint 加载 |
| `checkpointing.py:310` | 添加 `weights_only=True` | Legacy checkpoint 加载 |
| `mga_checkpoint.py:188` | 添加 `weights_only=True` | LayerZero checkpoint 加载 |
| `layerzero_checkpointer.py:55,110,127,135` | 添加 `weights_only=True` | ShardStateDict 加载 |

**修复代码示例**:
```python
# BEFORE (Vulnerable)
state_dict = torch.load(checkpoint_name, map_location='cpu')

# AFTER (Secure)
state_dict = torch.load(checkpoint_name, map_location='cpu', weights_only=True)
```

**兼容性处理**: 如果 checkpoint 包含非 tensor 数据导致 `weights_only=True` 失败，建议采用分层存储策略：
- 模型权重使用 safetensors 格式存储
- args、optimizer state 等元数据使用 JSON/YAML 存储

---

### 优先级 2: 短期修复（High 漏洞）

**分类修复建议**:

#### 2.1 数据处理工具漏洞（tools 模块）
| 漏洞 ID | 修复方案 |
|---------|----------|
| VULN-tools-load_dataset-001 | 禁止 `trust_remote_code=True` 参数注入，添加参数白名单验证 |
| VULN-tools-load_dataset-003 | 禁止直接执行用户提供的 Python 脚本，改用安全的数据处理管道 |
| VULN-CROSS-TOOLS-DATA-LOAD-001 | 对 `--input` 参数添加路径白名单验证，禁止远程数据源加载 |

**修复代码示例**:
```python
# 添加参数白名单
ALLOWED_LOAD_DATASET_PARAMS = ['path', 'split', 'cache_dir', 'streaming']
if args.hf_datasets_params:
    with open(args.hf_datasets_params, 'r') as fin:
        param_dict = json.load(fin)
    # 验证参数白名单
    for key in param_dict:
        if key not in ALLOWED_LOAD_DATASET_PARAMS:
            raise ValueError(f"Unauthorized parameter: {key}")
    # 强制禁用危险参数
    param_dict['trust_remote_code'] = False
    return load_dataset(**param_dict)
```

#### 2.2 竞态条件漏洞（NPUSwapManager）
修复 `NPUSwapManager::Init/DeInit` 的线程同步问题：
```cpp
// 添加 std::call_once 保护
static std::once_flag init_flag;
std::call_once(init_flag, [&]() {
    // 初始化逻辑
    isInit = true;
});
```

---

### 优先级 3: 计划修复（Medium/Low 漏洞）

**环境变量类型混淆修复**:
```python
# BEFORE (Type confusion)
_DEFAULT_QOS_SDMA_LOW = os.environ.get('QOS_SDMA_LOW', 2)

# AFTER (Explicit type conversion)
_DEFAULT_QOS_SDMA_LOW = int(os.environ.get('QOS_SDMA_LOW', '2'))
```

---

### 综合安全加固建议

#### 1. 实施 checkpoint 安全加载框架
```python
# 新建 mindspeed/security/checkpoint_validator.py
import os
import hashlib
from typing import List

ALLOWED_CHECKPOINT_DIRS = [
    "/data/checkpoints",
    "/models/pretrained",
    os.path.expanduser("~/.cache/torch/checkpoints"),
]

def validate_checkpoint_path(path: str) -> str:
    """验证 checkpoint 路径是否在白名单目录内"""
    real_path = os.path.realpath(path)
    if not any(real_path.startswith(allowed) for allowed in ALLOWED_CHECKPOINT_DIRS):
        raise SecurityError(f"Checkpoint path not allowed: {path}")
    return real_path

def secure_torch_load(path: str, expected_hash: str = None):
    """安全的 checkpoint 加载函数"""
    validated_path = validate_checkpoint_path(path)
    if expected_hash:
        with open(validated_path, 'rb') as f:
            if hashlib.sha256(f.read()).hexdigest() != expected_hash:
                raise SecurityError("Checkpoint integrity check failed")
    return torch.load(validated_path, map_location='cpu', weights_only=True)
```

#### 2. 迁移至 safetensors 格式
长期建议将 checkpoint 存储迁移至 safetensors 格式，该格式：
- 不使用 pickle，无任意代码执行风险
- 加载速度更快
- 支持懒加载（仅加载需要的层）

#### 3. 添加审计日志
记录所有 checkpoint 加载操作，用于安全审计：
```python
import logging
logging.info(f"Checkpoint loaded: {validated_path}, hash={file_hash}, user={os.getlogin()}")
```

---

## 9. 总结

本次扫描共发现 **12 个已确认漏洞**，核心风险集中在 checkpoint 反序列化（CWE-502，占比 50%）。MindSpeed 作为大模型训练加速库，checkpoint 加载是高频操作，安全漏洞影响面广、危害严重。

**关键行动项**:
1. ✅ **立即**: 在所有 `torch.load()` 调用添加 `weights_only=True`
2. ✅ **本周内**: 对 tools 模块数据处理参数添加白名单验证
3. ✅ **本月内**: 实施 checkpoint 路径白名单和完整性校验
4. ✅ **长期**: 迁移至 safetensors 格式，彻底消除 pickle 风险

---

*报告生成时间: 2025-04-20*
*扫描工具: OpenCode Multi-Agent Vulnerability Scanner*
