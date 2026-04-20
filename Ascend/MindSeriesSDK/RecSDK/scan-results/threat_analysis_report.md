# MindSeriesSDK RecSDK 威胁分析报告

> **分析模式：自主分析模式**
> 本次攻击面分析基于源码扫描和文档分析，未收到 threat.md 约束文件，AI 自主识别所有攻击面。

> **生成时间**: 2026-04-20
> **分析工具**: Architecture Agent (无 LSP 支持，使用 grep 回退方案)

---

## 1. 项目架构概览

### 1.1 项目定位

**MindSeriesSDK RecSDK** 是华为昇腾平台上的推荐系统训练 SDK，定位为 **机器学习库/SDK** 项目，而非网络服务或 CLI 工具。

| 属性 | 描述 |
|------|------|
| 项目类型 | 机器学习 SDK/库 (Python + C/C++ 混合) |
| 部署方式 | pip 安装的 Python 包，导入后调用 API 进行模型训练 |
| 目标用户 | 推荐系统算法工程师、训练集群运维人员 |
| 运行环境 | Atlas A2/A3 训练服务器，昇腾 NPU 设备 |
| 语言组成 | C/C++ 721 文件 (76,685 行) + Python 455 文件 (48,660 行) |

### 1.2 核心架构

项目分为两大核心模块：

**自定义算子模块 (cust_op)**
- **ascendc_op**: Ascend C 编写的算子，编译后在 AI Core 执行（45+ 算子类型）
- **framework/torch_plugin**: PyTorch 自定义算子适配层（30+ 算子）
- **framework/tf_plugin**: TensorFlow 自定义算子插件
- **tf_cpu_op**: Kunpeng CPU 算子
- **hkv**: HierarchicalKV 存储子模块

**训练框架模块 (training)**
- **tf_rec_v1**: TensorFlow 非全下沉稀疏推荐框架
- **tf_rec_v2**: TensorFlow 全下沉稀疏推荐框架 (POC)
- **torch_rec_v1**: PyTorch + TorchRec 非全下沉框架
- **torch_rec_v2**: PyTorch + TorchRec 全下沉框架（含 dynamic_emb）
- **common**: 公共组件（通信、验证、日志、性能调优）

### 1.3 数据流概览

```
用户训练脚本 (Python)
    │
    ├── 训练数据加载 (外部数据文件)
    │       └── Dataset/DataLoader
    │
    ├── 配置初始化
    │       ├── TOML 配置文件 (mxrec)
    │       ├── Rank Table JSON (HCCL 分布式)
    │       └── 模型配置参数
    │
    ├── 模型训练循环
    │       ├── 自定义算子调用 (torch.ops.mxrec.* / tf.custom_op)
    │       │       └── NPU 算子执行 (ascendc_op)
    │       ├── Embedding Cache 操作
    │       └── 分布式通信 (LCCL socket)
    │
    └── 模型保存/加载
            ├── Checkpoint 文件 (JSON index + 二进制数据)
            └── Sparse attributes JSON
```

---

## 2. 模块风险评估

### 2.1 高风险模块 (Critical/High)

| 模块 | 文件数 | 风险等级 | 主要威胁 |
|------|--------|----------|----------|
| lccl_socket_comm | 10 | **Critical** | 网络通信、socket 操作、数据接收无验证 |
| tf_rec_v1/saver | 15 | **High** | JSON 文件加载、文件路径操作、模型 checkpoint 处理 |
| training_common/hccl | 20 | **High** | Rank table JSON 加载、环境变量依赖、分布式配置 |
| tf_rec_v2/config | 10 | **High** | TOML 配置解析、文件路径验证 |
| cust_op_framework | 75 | **Medium** | 自定义算子 API 入口、用户可控 tensor 数据 |

### 2.2 模块威胁详情

#### lccl_socket_comm (Critical)

**核心文件**: `training/common/src/core/lccl/src/tools/socket/lcal_sock_exchange.cpp`

**威胁场景**:
- TCP socket 服务器在分布式训练节点间通信
- `bind()`, `listen()`, `accept()` 操作暴露网络接口
- `recv()` 接收数据后直接使用 `memcpy_s` 复制，无内容验证
- 端口配置来自 rank table 文件，攻击者可能篡改 rank table 导致连接恶意节点

**缓解因素**:
- 通信仅在训练集群内部进行
- Rank table 文件由管理员控制
- 数据来自信任的训练进程

#### tf_rec_v1/saver (High)

**核心文件**: `training/tf_rec_v1/python/saver/saver.py`, `sparse.py`

**威胁场景**:
- `json.load()` 加载 model_index.json 和 sparse attributes 文件
- 文件路径来自用户训练脚本参数 `save_path`
- 多处文件读写操作使用 `os.fdopen()` 和 `tf.io.gfile`
- `merge_slice_files()` 读取并合并切片数据文件

**缓解因素**:
- 使用 `SAVE_FILE_FLAG` 安全文件打开模式
- `DirectoryValidator` 检查软链接
- 文件路径由用户训练脚本控制，非远程输入

#### training_common/hccl (High)

**核心文件**: `training/common/python/communication/hccl/hccl_mgmt.py`

**威胁场景**:
- `json.load()` 加载 rank table 文件（路径来自环境变量 `RANK_TABLE_FILE`)
- 解析 rank_id 和 device_id，使用 `int_safe_check` 验证范围
- 文件格式解析逻辑复杂，存在格式混淆风险

**缓解因素**:
- `class_safe_check` 和 `int_safe_check` 提供类型和范围验证
- 文件路径来自环境变量，由集群部署系统控制
- 异常处理覆盖文件不存在和 JSON 解析错误

#### cust_op_framework (Medium)

**核心文件**: `cust_op/framework/torch_plugin/torch_library/*.cpp`, `cust_op/framework/tf_plugin/src/*.cpp`

**威胁场景**:
- 自定义算子通过 Python API 调用（`torch.ops.mxrec.*`, `tf.custom_op`)
- 用户传入任意 tensor 数据和参数
- 参数验证依赖 `TORCH_CHECK` 和 Attr 定义约束
- 算子在 NPU 上执行，无传统内存边界检查

**缓解因素**:
- `hstu_common.h` 提供参数范围验证 (MaskCheck, MaxSeqLenCheck)
- TensorFlow 算子使用 ShapeFn 强制输入维度约束
- 算子文档明确参数约束条件

---

## 3. 攻击面分析

### 3.1 信任边界模型

```
┌─────────────────────────────────────────────────────────────────┐
│                    Training Cluster Environment                  │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │            Trusted: SDK Internal Implementation           │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌──────────────────┐   │ │
│  │  │ Torch Ops   │  │ TF Ops      │  │ Ascend C Ops     │   │ │
│  │  │ Validation  │  │ ShapeFn     │  │ Kernel Operator  │   │ │
│  │  └─────────────┘  └─────────────┘  └──────────────────┘   │ │
│  │                                                            │ │
│  │  ┌─────────────────────────────────────────────────────┐  │ │
│  │  │        LCCL Socket (semi_trusted: cluster peers)    │  │ │
│  │  │  bind/listen/accept → recv/send → memcpy_s          │  │ │
│  │  └─────────────────────────────────────────────────────┘  │ │
│  └───────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌────────────────────── Attack Surfaces ─────────────────────┐ │
│  │ [1] Configuration Files (trusted_admin: TOML, Rank Table) │ │
│  │ [2] Model Checkpoints (trusted_admin: JSON + binary)      │ │
│  │ [3] User API Parameters (untrusted_local: tensors, paths)│ │
│  │ [4] Distributed Network (semi_trusted: TCP socket)       │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌────────────────────── External ─────────────────────────────┐ │
│  │ User Training Scripts │ Training Data Files │ Cluster Admin│ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 入口点清单

| 入口类型 | 文件位置 | 函数 | 信任等级 | 可达性分析 |
|----------|----------|------|----------|------------|
| **Network** | lccl_sock_exchange.cpp:217 | InitServer | semi_trusted | TCP socket 仅在集群内部可达，端口来自配置 |
| **Network** | lccl_sock_exchange.cpp:255 | AcceptConnection | semi_trusted | 接收来自 rank table 指定的训练节点连接 |
| **Network** | lccl_sock_exchange.cpp:85 | Recv | semi_trusted | 接收来自可信训练节点的数据 |
| **File** | parser.py:90 | _parse_config | trusted_admin | TOML 文件由管理员/部署脚本控制 |
| **File** | hccl_mgmt.py:98 | _get_rank_info_with_ranktable | trusted_admin | Rank table 由集群部署系统生成 |
| **File** | saver.py:935 | update_model_index | trusted_admin | 模型文件路径来自用户训练脚本 |
| **File** | sparse.py:81 | load_sparse_attributes | trusted_admin | 稀疏属性文件来自用户 checkpoint |
| **API** | hstu_jagged.cpp | TORCH_LIBRARY_IMPL | untrusted_local | 用户可调用算子传入任意 tensor |
| **API** | block_bucketize_sparse_features.cpp | TORCH_LIBRARY_FRAGMENT | untrusted_local | 用户可传入 bucketize 参数 |
| **API** | cust_embedding_by_address.cpp | REGISTER_OP | untrusted_local | 用户可传入 address tensor |
| **CmdLine** | setup_common.py:114 | run_build_scripts | trusted_admin | 仅在安装时执行，非运行时入口 |

### 3.3 排除的入口点

以下候选入口点经分析后**排除**：

| 原入口 | 排除原因 |
|--------|----------|
| `getenv()` 调用 | 环境变量由训练集群部署系统控制，非用户可控 |
| `setup.py` 中的 subprocess | 仅在 pip install 时执行，非运行时入口 |
| 测试文件中的 `if __name__ == "__main__"` | 测试脚本非生产环境入口 |
| `torch.load()` 调用 | 加载预生成的测试数据，可信来源 |

---

## 4. STRIDE 威胁建模

### 4.1 Spoofing (欺骗)

| 威胁场景 | 影响组件 | 风险等级 | 缓解措施 |
|----------|----------|----------|----------|
| Rank table 文件篡改导致连接恶意节点 | lccl_socket_comm | Medium | Rank table 由集群部署系统控制；需验证节点身份 |
| 配置文件伪造导致训练参数错误 | config/parser | Low | TOML 文件由管理员控制；file_safe_check 验证路径 |

### 4.2 Tampering (篡改)

| 威胁场景 | 影响组件 | 风险等级 | 缓解措施 |
|----------|----------|----------|----------|
| 模型 checkpoint 文件篡改导致加载恶意模型 | saver/sparse | Medium | 使用安全文件打开模式；DirectoryValidator 检查路径 |
| 网络数据篡改导致训练结果错误 | lccl_socket | Medium | 数据来自可信训练节点；无完整性验证机制 |
| Embedding cache 数据篡改导致模型精度下降 | cache_manager | Low | 数据来自内部 cache；memcpy_s 操作 |

### 4.3 Repudiation (抵赖)

| 威胁场景 | 影响组件 | 风险等级 | 缓解措施 |
|----------|----------|----------|----------|
| 无法追溯模型 checkpoint 来源 | saver | Low | 无审计日志记录 checkpoint 操作 |
| 分布式训练操作无日志 | lccl_socket | Low | 有 ASD_LOG 日志但未记录完整审计信息 |

### 4.4 Information Disclosure (信息泄露)

| 威胁场景 | 影响组件 | 风险等级 | 缓解措施 |
|----------|----------|----------|----------|
| 配置文件泄露训练参数 | config/parser | Low | TOML 文件权限由管理员控制 |
| 模型文件泄露训练数据和模型结构 | saver | Medium | 模型文件路径由用户控制；需用户管理文件权限 |
| 网络通信泄露训练数据 | lccl_socket | Medium | 通信仅在集群内部；未加密传输 |

### 4.5 Denial of Service (拒绝服务)

| 威胁场景 | 影响组件 | 风险等级 | 缓解措施 |
|----------|----------|----------|----------|
| 网络攻击导致分布式训练中断 | lccl_socket | Medium | Socket 操作有错误处理；超时机制待确认 |
| 配置文件损坏导致训练无法启动 | config/parser | Low | 异常处理覆盖文件不存在和解析错误 |
| 算子参数越界导致 NPU 执行失败 | cust_op | Low | TORCH_CHECK 参数验证；算子文档说明约束 |

### 4.6 Elevation of Privilege (权限提升)

| 娕胁场景 | 影响组件 | 风险等级 | 缓解措施 |
|----------|----------|----------|----------|
| 配置文件注入恶意参数 | config/parser | Low | TOML 文件由管理员控制；参数验证依赖业务逻辑 |
| 模型文件注入恶意代码 | saver | Low | 无代码执行功能；仅加载数据 |
| 自定义算子参数导致内存越界 | cust_op | Medium | TORCH_CHECK 约束；但 NPU 算子无传统边界检查 |

---

## 5. 安全加固建议（架构层面）

### 5.1 网络通信加固

1. **身份验证**: LCCL socket 通信应增加节点身份验证机制，防止 rank table 突改导致的恶意连接
2. **数据完整性**: 对分布式训练数据增加校验机制（如 HMAC 或 checksum）
3. **传输加密**: 对敏感训练数据考虑 TLS 加密（当前未加密传输）

### 5.2 配置文件安全

1. **文件权限**: 明确要求 TOML 和 rank table 文件仅对管理员可写
2. **内容签名**: 对配置文件增加数字签名验证（可选，取决于部署环境）
3. **路径白名单**: 对配置文件路径增加白名单验证（当前仅 file_safe_check）

### 5.3 模型文件安全

1. **文件权限**: 在文档中明确建议用户管理 checkpoint 文件权限
2. **完整性校验**: 对模型 checkpoint 增加 hash 校验，防止文件篡改
3. **安全加载**: 对 JSON 加载增加更严格的 schema 验证

### 5.4 自定义算子安全

1. **参数验证**: 完善所有自定义算子的参数边界检查（当前部分算子有验证）
2. **输入约束**: 在文档中明确所有算子的输入约束条件
3. **异常处理**: 增加算子执行失败的详细错误信息和恢复机制

### 5.5 日志与审计

1. **审计日志**: 对 checkpoint 保存/加载操作增加审计日志记录
2. **安全事件**: 对分布式通信异常增加安全事件日志
3. **访问记录**: 记录配置文件和模型文件的访问时间

---

## 6. 扫描范围建议

基于本次架构分析，建议后续漏洞扫描重点关注：

### 6.1 高优先级扫描目标

| 目标模块 | 扫描重点 | 原因 |
|----------|----------|------|
| lccl_sock_exchange.cpp | 网络输入验证、内存操作 | Critical 风险，网络数据直接 memcpy |
| saver.py, sparse.py | JSON 解析、文件路径操作 | High 风险，模型文件处理 |
| hccl_mgmt.py | JSON 解析、环境变量依赖 | High 风险，分布式配置 |
| parser.py | TOML 解析、文件路径验证 | High 风险，配置解析 |

### 6.2 中优先级扫描目标

| 目标模块 | 扫描重点 | 原因 |
|----------|----------|------|
| cust_op/framework | 算子参数验证、内存边界 | Medium 风险，用户可控输入 |
| cache_manager.cpp | memcpy_s 操作 | Medium 风险，内存操作 |
| dynamic_emb | load/save 操作 | Medium 风险，文件操作 |

### 6.3 低优先级扫描目标

| 目标模块 | 扫描重点 | 原因 |
|----------|----------|------|
| ascendc_op | 算子实现逻辑 | NPU 算子，依赖昇腾 SDK 安全 |
| tf_cpu_op | CPU 算子 | Kunpeng 算子，风险较低 |
| 测试文件 | 测试用例逻辑 | 非生产代码 |

---

## 附录

### A. 文件统计

| 类别 | 文件数 | 行数 |
|------|--------|------|
| C/C++ (cust_op) | 721 | 76,685 |
| Python (training) | 455 | 48,660 |
| 总计 | 1,176 | 125,345 |

### B. LSP 可用性说明

本次分析 **LSP 不可用**：
- **C/C++ LSP**: 缺少昇腾 SDK 头文件 (`kernel_operator.h`, `tilingdata_base.h`)
- **Python LSP**: `pyright-langserver` 未安装

后续扫描使用 grep 回退方案进行跨文件分析。

### C. 分析局限性

1. Ascend C 算子依赖昇腾 SDK，无法完整分析其实现逻辑
2. NPU 算子执行环境与传统 CPU 内存模型不同，边界检查机制待确认
3. 部分第三方依赖（如 hkv 子模块）未深入分析

---

**报告结束**

> 本报告由 Architecture Agent 生成，供后续 Scanner 和 Verification Agent 参考。
> 具体漏洞代码片段、修复建议和统计数据将由 Reporter Agent 在最终报告中提供。