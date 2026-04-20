# MindSpeed 威胁分析报告

> **分析模式：自主分析模式**
> 本次攻击面分析未受 threat.md 约束，AI 自主识别了所有潜在攻击面和高风险模块。

## 项目架构概览

### 项目定位

MindSpeed Core 是华为昇腾（Ascend NPU）的大模型加速库，作为 Megatron-LM 的适配层，主要功能包括：

1. **适配层**：通过动态 patch 机制修改 Megatron-LM 的行为，使其能在昇腾 NPU 上运行
2. **自定义算子**：提供 C++ 实现的昇腾亲和算子（如 rotary_embedding, flash_attention, MoE 等）
3. **内存优化**：实现智能内存交换、重计算等内存管理功能
4. **自动配置**：提供自动并行策略搜索系统

### 项目类型判定

| 维度 | 结论 |
|------|------|
| 主要类型 | **Library/SDK** |
| 次要类型 | CLI 工具（patch 管理、数据预处理） |
| 语言组成 | Python 911 文件（约 143,598 行） + C/C++ 49 文件（约 12,480 行） |
| 部署模式 | pip install 后作为库导入，运行在昇腾 NPU 集群 |

### 信任边界模型

系统存在以下信任边界：

| 边界 | 可信侧 | 不可信侧 | 风险等级 |
|------|--------|----------|----------|
| Checkpoint Files | 应用逻辑 | 外部 checkpoint/模型文件 | **High** |
| CLI Arguments | 应用逻辑 | 本地用户输入 | Medium |
| Environment Variables | 应用逻辑 | 部署环境配置 | Low |
| Patch Files | 应用逻辑 | 本地 patch 文件 | Medium |
| Tokenizer Files | 应用逻辑 | 外部 tokenizer 模型 | Medium |

## 模块风险评估

### 高风险模块列表

| 优先级 | 模块 | 文件路径 | 语言 | 风险等级 | 风险类型 |
|--------|------|----------|------|----------|----------|
| 1 | checkpointing | mindspeed/checkpointing.py | python | **Critical** | 反序列化漏洞（torch.load） |
| 2 | layerzero | mindspeed/core/distributed/layerzero/state/mga_checkpoint.py | python | **Critical** | 反序列化漏洞（torch.load） |
| 3 | run | mindspeed/run/run.py | python | **High** | 命令执行（subprocess.run） |
| 4 | auto_settings | mindspeed/auto_settings/mindspeed_adaptor/mindspeed_runner.py | python | **High** | 命令执行（subprocess.Popen） |
| 5 | core | mindspeed/core/qos/qos.py | python | Medium | 命令执行（subprocess） |
| 6 | auto_settings | mindspeed/auto_settings/utils/file_utils.py | python | Medium | pickle 反序列化（受限） |
| 7 | tokenizer | mindspeed/tokenizer/tokenizer.py | python | Medium | 外部模型加载 |
| 8 | tools | tools/preprocess_data.py | python | Medium | 外部数据加载 |
| 9 | mindspeed | mindspeed/megatron_adaptor.py | python | Medium | 导入时自动执行 patch |
| 10 | pluggable_allocator | mindspeed/ops/csrc/pluggable_allocator | c_cpp | Medium | 内存管理 |

### 模块分类统计

| 类别 | 风险等级 | 文件数 | 说明 |
|------|----------|--------|------|
| 反序列化/Checkpoint | Critical | 3 | 使用 torch.load 加载外部 checkpoint |
| 命令执行 | High | 3 | 使用 subprocess 执行外部命令 |
| 文件加载 | Medium | 4 | 加载外部 tokenizer、数据集等 |
| 内存管理 | Medium | 5 | C++ 内存分配器和交换管理器 |
| 配置/参数 | Low | 多个 | YAML 配置、命令行参数解析 |

## 攻击面分析

### 识别的入口点

| 入口点 | 文件 | 函数 | 类型 | 信任等级 | 风险 |
|--------|------|------|------|----------|------|
| CLI 入口 | mindspeed/run/run.py | main | cmdline | untrusted_local | 命令注入风险 |
| Checkpoint 加载 | mindspeed/checkpointing.py | _load_base_checkpoint | file | semi_trusted | 反序列化风险 |
| LayerZero Checkpoint | mindspeed/core/distributed/layerzero/state/mga_checkpoint.py | load_layerzero_checkpoint | file | semi_trusted | 反序列化风险 |
| Tokenizer 加载 | mindspeed/tokenizer/tokenizer.py | _AutoTokenizer.__init__ | file | semi_trusted | 外部模型风险 |
| 数据预处理 | tools/preprocess_data.py | main | cmdline | untrusted_local | 数据注入风险 |
| 自动配置执行 | mindspeed/auto_settings/mindspeed_adaptor/mindspeed_runner.py | MindSpeedRunner.run | cmdline | semi_trusted | 命令执行风险 |
| 库入口 | mindspeed/megatron_adaptor.py | patch_features | decorator | trusted_admin | runtime patch |
| 环境变量配置 | mindspeed/core/qos/qos.py | Qos.__init__ | env | trusted_admin | 配置注入 |

### 关键数据流路径

1. **Checkpoint 反序列化路径**
   ```
   load_dir (args) → get_checkpoint_name → _load_base_checkpoint → torch.load
   ```
   风险：如果 checkpoint 文件被恶意替换，torch.load 反序列化可能导致代码执行

2. **Patch 命令执行路径**
   ```
   argv → parse_args → patch_from_args → subprocess.run (git apply)
   ```
   风险：patch 文件路径来自扫描目录，如果目录中有恶意文件可能被处理

3. **分布式训练执行路径**
   ```
   args → MindSpeedRunner.run → subprocess.Popen (torchrun)
   ```
   风险：参数来自配置，可能影响命令执行

4. **Tokenizer 加载路径**
   ```
   tokenizer_name_or_path (args) → _AutoTokenizer.__init__ → AutoTokenizer.from_pretrained
   ```
   风险：加载外部 tokenizer 模型，如果路径被控制可能加载恶意模型

5. **受限 Pickle 加载路径**
   ```
   file_path → restricted_read → _RestrictedUnpickler.load
   ```
   风险：实现了受限 Unpickler，仅允许 mindspeed.auto_settings 模块的类，降低了风险

## STRIDE 威胁建模

### 1. Spoofing (欺骗)

| 威胁场景 | 风险等级 | 描述 |
|----------|----------|------|
| Checkpoint 来源欺骗 | Medium | 如果 checkpoint 文件来自不可信来源，可能包含恶意数据 |
| Tokenizer 来源欺骗 | Low | HuggingFace tokenizer 可能有签名验证机制 |

### 2. Tampering (篡改)

| 威胁场景 | 风险等级 | 描述 |
|----------|----------|------|
| Checkpoint 文件篡改 | **High** | checkpoint 文件被篡改可能导致模型行为异常或代码执行 |
| Patch 文件篡改 | Medium | patch 文件被篡改可能修改源代码行为 |
| YAML 配置篡改 | Low | 配置文件篡改可能影响训练参数 |

### 3. Repudiation (抵赖)

| 威胁场景 | 风险等级 | 描述 |
|----------|----------|------|
| 操作日志缺失 | Low | 作为库，日志依赖调用方管理 |

### 4. Information Disclosure (信息泄露)

| 威胁场景 | 风险等级 | 描述 |
|----------|----------|------|
| Checkpoint 数据泄露 | Medium | checkpoint 包含模型权重，可能泄露知识产权 |
| 训练数据泄露 | Low | 数据处理过程中可能泄露敏感信息 |

### 5. Denial of Service (拒绝服务)

| 威势场景 | 风险等级 | 描述 |
|----------|----------|------|
| 内存耗尽 | Medium | C++ 内存管理器可能因异常导致内存泄漏 |
| 无限循环 patch | Low | patch 应用失败可能导致处理循环 |

### 6. Elevation of Privilege (权限提升)

| 势场景 | 风险等级 | 描述 |
|----------|----------|------|
| torch.load 反序列化 | **Critical** | 如果 checkpoint 包含恶意序列化数据，可能导致任意代码执行 |
| subprocess 命令注入 | High | 如果参数可控，可能执行恶意命令 |

## 安全加固建议（架构层面）

### 1. 反序列化安全加固（Critical）

- **torch.load 加固**：
  - 使用 `torch.load(..., weights_only=True)` 限制只加载权重数据
  - 添加 checkpoint 文件校验机制（如 SHA256 哈希验证）
  - 对 checkpoint 来源进行白名单控制

- **参考实现**：
  ```python
  # 建议使用 weights_only=True
  state_dict = torch.load(checkpoint_name, map_location='cpu', weights_only=True)
  ```

### 2. 命令执行安全加固（High）

- **subprocess 命令加固**：
  - 使用参数列表而非字符串拼接
  - 验证命令参数来源，避免用户直接控制
  - 添加命令执行审计日志

### 3. 文件加载安全加固（Medium）

- **Tokenizer 加载加固**：
  - 使用 `local_files_only=True` 避免网络下载（已实现）
  - 使用 `trust_remote_code=False` 避免执行远程代码（已实现）
  - 添加 tokenizer 路径验证

- **数据集加载加固**：
  - 验证数据集来源
  - 添加数据格式校验

### 4. C++ 内存管理加固（Medium）

- **内存分配器加固**：
  - 添加边界检查
  - 实现异常处理机制
  - 限制内存分配上限

### 5. 整体安全建议

- 添加安全配置文件，限制可加载的文件路径
- 实现文件来源签名验证机制
- 增强日志记录，记录所有敏感操作
- 定期进行安全审计和依赖更新

## 总结

MindSpeed 作为大模型加速库，主要风险集中在：

1. **Checkpoint 反序列化**：使用 torch.load 加载外部 checkpoint 文件是最高风险点，可能导致任意代码执行
2. **命令执行**：CLI 工具使用 subprocess 执行外部命令，需要参数验证
3. **外部模型加载**：加载 tokenizer 等外部模型需要注意来源验证

建议优先关注 checkpointing.py 和 mga_checkpoint.py 中的 torch.load 调用，添加 `weights_only=True` 参数和文件校验机制。