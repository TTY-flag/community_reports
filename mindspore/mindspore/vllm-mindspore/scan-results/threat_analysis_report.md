# vLLM-MindSpore 威胁分析报告

> **分析模式：自主分析模式**
> 本次攻击面分析由 Architecture Agent 自主识别，项目根目录下未检测到 threat.md 约束文件。

## 项目架构概览

### 项目基本信息

- **项目名称**: vLLM-MindSpore
- **项目类型**: Python + C/C++ 混合项目（库/插件）
- **主要功能**: MindSpore 大模型推理引擎适配器，将 MindSpore 推理能力接入 vLLM
- **总文件数**: 154 个（Python 148 + C/C++ 6）
- **总代码行数**: ~33,106 行

### 核心组件架构

```
vLLM-MindSpore 插件架构
├── entrypoints/           # API入口点（OpenAI兼容）
│   ├── __main__.py        # 动态模块加载执行
│   └── openai/            # OpenAI API处理
│       ├── serving_chat.py      # Chat流式响应
│       └── tool_parsers/        # 工具调用解析
├── model_executor/        # 模型执行器
│   ├── model_loader/      # 模型加载（权重处理）
│   ├── models/            # 模型实现（DeepSeek, Qwen等）
│   └── layers/            # 神经网络层
├── v1/                    # V1架构
│   ├── worker/            # Worker进程（NUMA绑定、性能分析）
│   ├── engine/            # 引擎核心
│   └── sample/            # 采样器
├── executor/              # 分布式执行器（Ray集群）
├── lora/                  # LoRA适配器
├── multimodal/            # 多模态输入处理
├── csrc/                  # C/C++自定义算子（Ascend NPU）
└── dashboard/             # 基准测试工具（高风险）
```

### 项目定位分析

本项目是一个 **vLLM 后端插件**，其典型部署方式为：

1. **作为库使用**: 用户通过 `pip install vllm-mindspore` 安装，然后通过 CLI 启动服务
2. **作为服务运行**: `vllm-mindspore serve <model>` 启动 HTTP API 服务
3. **依赖关系**: 依赖 vLLM 框架，通过 monkey patch 替换 PyTorch 组件为 MindSpore 实现

### 信任边界模型

| 信任边界 | 可信侧 | 不可信侧 | 风险等级 |
|---------|--------|---------|---------|
| Network Interface (HTTP API) | vLLM-MindSpore Plugin | 远程客户端推理请求 | High |
| Model Loading Interface | 插件内部 | 外部模型权重文件（HuggingFace/本地路径） | Medium |
| Environment Configuration | 插件内部 | 部署脚本设置的环境变量 | Low |
| Dashboard/Testing Tools | Dashboard脚本 | 基准测试执行的shell命令 | Medium |

## 模块风险评估

### 高风险模块（Critical/High）

| 模块 | 文件 | 风险等级 | 主要风险 | STRIDE威胁 |
|------|------|----------|---------|-----------|
| dashboard | acc.py | **Critical** | shell=True命令执行，命令注入风险 | T, E |
| entrypoints | __main__.py | **High** | 动态执行模块代码 | T, E |
| model_executor | weight_utils.py | **High** | 加载外部模型权重文件 | T, I |
| entrypoints | serving_chat.py | **High** | 处理外部HTTP请求 | T, I, D |
| v1/worker | gpu_model_runner.py | **High** | 处理推理请求 | D |

### 中等风险模块（Medium）

| 模块 | 文件 | 风险等级 | 主要风险 |
|------|------|----------|---------|
| entrypoints | deepseekv3_tool_parser.py | Medium | 正则处理外部输入 |
| model_executor | utils.py | Medium | 模型架构解析 |
| executor | ray_utils.py | Medium | Ray集群环境配置 |
| v1/worker | gpu_worker.py | Medium | 执行系统命令获取NUMA拓扑 |
| v1/worker | profile.py | Medium | 性能分析工具 |
| build | setup.py | Medium | 构建脚本执行bash命令 |

### 低风险模块（Low）

| 模块 | 文件 | 风险等级 | 说明 |
|------|------|----------|------|
| csrc | *.c/*.cpp | Low | 简单的C扩展模块，无外部输入处理 |
| platforms | ascend.py | Low | 平台适配，无外部输入 |
| distributed | shm_broadcast.py | Low | 共享内存通信 |
| examples | offline_inference/ | Low | 示例代码 |

## 攻击面分析

### 1. CLI 命令行入口

**入口点**: `vllm_mindspore/scripts.py:main()`

- **信任等级**: trusted_admin
- **攻击者可达性**: 需要本地访问权限启动服务
- **数据可控性**: 管理员可控制启动参数
- **风险**: Medium - 主要风险来自传入的模型路径参数

### 2. 动态模块执行

**入口点**: `vllm_mindspore/entrypoints/__main__.py:__main__`

- **信任等级**: semi_trusted
- **攻击者可达性**: 需要通过CLI传入模块名
- **风险分析**:
  - 代码动态获取模块源码并执行
  - 模块名来自 sys.argv[1]
  - 源码来自 inspect.getsource(module)
  - **潜在风险**: 如果传入恶意模块名，可能导致代码执行

### 3. 模型权重加载

**入口点**: `vllm_mindspore/model_executor/model_loader/weight_utils.py`

- **信任等级**: semi_trusted
- **攻击者可达性**: 用户指定模型路径或HuggingFace模型ID
- **风险分析**:
  - 加载外部 safetensors 文件
  - 使用 `safe_open()` 库处理
  - **潜在风险**: 恶意模型文件可能导致内存问题或反序列化漏洞

### 4. Dashboard 工具（高风险）

**入口点**: `dashboard/acc.py`

- **信任等级**: untrusted_local
- **攻击者可达性**: 本地用户可调用基准测试脚本
- **风险分析**:
  - 多处使用 `shell=True` 执行命令
  - `exec_shell_cmd()` 直接执行传入的 cmd 字符串
  - `shell_sed_cmd()` 执行 sed 命令修改文件
  - **潜在风险**: 命令注入，路径注入

### 5. OpenAI API 处理（继承自 vLLM）

**入口点**: `vllm_mindspore/entrypoints/openai/serving_chat.py`

- **信任等级**: untrusted_network (继承自 vLLM)
- **攻击者可达性**: HTTP API 公网可达（取决于部署）
- **风险分析**:
  - 处理外部 HTTP 请求
  - 使用正则解析工具调用
  - 流式响应处理
  - **潜在风险**: 输入验证不足，正则 ReDoS

## STRIDE 威胁建模

### Spoofing (欺骗)

| 组件 | 威胁描述 | 风险等级 |
|------|---------|---------|
| OpenAI API | 无认证机制，依赖 vLLM 框架 | Medium |
| Ray集群 | Ray actor 通信可能被伪造 | Low |

### Tampering (篡改)

| 组件 | 威胁描述 | 风险等级 |
|------|---------|---------|
| 模型权重文件 | 外部模型文件可能被篡改 | High |
| 配置文件 | 环境变量可能被篡改 | Medium |
| Dashboard sed命令 | shell_sed_cmd 可能篡改文件 | High |

### Repudiation (抵赖)

| 组件 | 威胁描述 | 风险等级 |
|------|---------|---------|
| API日志 | 依赖 vLLM 框架日志机制 | Low |
| 性能分析 | Profiler 输出路径来自环境变量 | Low |

### Information Disclosure (信息泄露)

| 组件 | 威胁描述 | 风险等级 |
|------|---------|---------|
| 模型权重 | 加载过程可能泄露模型结构 | Medium |
| 推理结果 | API 响应可能泄露敏感信息 | Medium |
| 系统信息 | NUMA拓扑信息通过lscui/npu-smi获取 | Low |

### Denial of Service (拒绝服务)

| 组件 | 威胁描述 | 风险等级 |
|------|---------|---------|
| 推理请求 | 大量请求可能耗尽NPU资源 | High |
| 正则解析 | 复杂正则可能导致 ReDoS | Medium |
| 内存分配 | KV Cache 内存池可能耗尽 | Medium |

### Elevation of Privilege (权限提升)

| 组件 | 威胁描述 | 风险等级 |
|------|---------|---------|
| shell=True | Dashboard 工具命令注入可能提权 | Critical |
| 动态执行 | __main__.py 动态执行模块代码 | High |
| NUMA绑定 | bind_cpu 需要权限设置CPU亲和性 | Low |

## 安全加固建议

### 架构层面建议

### 1. Dashboard 工具安全加固（Critical）

```
问题: dashboard/acc.py 使用 shell=True 执行命令
建议:
- 移除 shell=True，使用 subprocess.run(cmd_list, shell=False)
- 对传入的 cmd 参数进行严格验证和白名单过滤
- 使用 shlex.quote() 对路径参数进行转义
- 考虑将 Dashboard 工具与核心插件分离，仅用于开发测试
```

### 2. 动态模块执行加固（High）

```
问题: entrypoints/__main__.py 动态执行模块代码
建议:
- 对模块名进行白名单验证
- 验证模块是否来自可信来源（vllm.entrypoints）
- 添加沙箱隔离机制
- 考虑移除动态执行，直接导入已知模块
```

### 3. 模型权重加载加固（High）

```
问题: 加载外部 safetensors 文件
建议:
- 添加模型文件完整性校验（SHA256）
- 验证模型来源（仅允许可信的HuggingFace仓库）
- 限制模型路径（禁止目录遍历）
- 添加文件大小限制防止内存耗尽
```

### 4. OpenAI API 处理加固

```
问题: 继承 vLLM 的 API 安全风险
建议:
- 添加输入验证层（请求参数校验）
- 限制正则复杂度防止 ReDoS
- 添加请求速率限制
- 配置 API 认证（如需要）
```

### 5. 环境变量安全

```
问题: 多处读取环境变量配置
建议:
- 敏感环境变量使用 secure_getenv
- 验证环境变量值格式
- 添加默认安全配置
- 记录环境变量修改日志
```

### 代码层面建议

1. **输入验证**: 所有来自外部的输入（模型路径、请求参数、环境变量）应进行验证
2. **命令执行**: 禁止使用 shell=True，使用参数列表形式
3. **正则安全**: 检查正则表达式复杂度，避免 ReDoS
4. **错误处理**: 不要在错误消息中暴露敏感信息
5. **日志安全**: 确保日志不包含敏感数据

## 总结

vLLM-MindSpore 是一个将 MindSpore 大模型推理能力接入 vLLM 的后端插件。主要安全风险集中在：

1. **Dashboard 工具的 shell=True 命令执行**（Critical）- 这是最高风险点
2. **动态模块执行机制**（High）- 潜在的代码注入风险
3. **外部模型文件加载**（High）- 模型完整性风险
4. **继承自 vLLM 的 API 入口**（High）- 网络攻击面

建议优先处理 Dashboard 工具的安全问题，其次是加固模型加载和动态执行机制。C/C++ 代码风险较低，主要是简单的扩展模块。

---
*报告生成时间: 2026-04-23T18:58:00Z*
*分析Agent: @architecture*