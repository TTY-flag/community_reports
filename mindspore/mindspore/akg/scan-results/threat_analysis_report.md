# AKG 项目攻击面分析报告

## 项目概况

| 属性 | 值 |
|------|-----|
| 项目名称 | Auto Kernel Generator (AKG) |
| 项目类型 | C/C++ + Python 混合项目 |
| C/C++ 文件数 | 277 个 |
| Python 文件数 | 1249 个 |
| C/C++ 代码行数 | ~56,775 行 |
| 主要模块 | akg-mlir (MLIR编译器), aikg (AI Kernel Generator) |

## 项目简介

AKG 是一个深度学习编译器，用于优化深度神经网络算子并提供算子自动融合功能。项目包含两个主要子项目：

- **AIKG**: AI驱动的内核生成器，使用LLM生成GPU/NPU内核代码，支持 Triton-Ascend、SWFT、CUDA C 等DSL
- **AKG-MLIR**: 基于 MLIR 开源项目演进的深度学习编译器，提供 CPU/GPU/Ascend 算子编译 Pipeline

## 攻击面概览

### 漏洞严重性统计

| 严重性 | 数量 | 主要类型 |
|--------|------|----------|
| Critical | 5 | RCE、命令注入、代码注入 |
| High | 15 | SSRF、模板注入、文件IO |
| Medium | 20 | JSON解析、SSL禁用、环境变量 |

### 攻击面分类

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         AKG 攻击面全景图                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────────────┐     ┌──────────────────────┐                 │
│  │   Web API 入口       │     │   CLI 工具入口        │                 │
│  │  (Critical)          │     │  (Critical)          │                 │
│  │                      │     │                      │                 │
│  │  Worker Server       │     │  ascend-linker       │                 │
│  │  POST /verify        │────▶│  popen() 命令注入    │                 │
│  │  POST /profile       │     │                      │                 │
│  │                      │     │  ptx-replace         │                 │
│  │  Main Server         │     │  文件读写            │                 │
│  │  workers/register    │     │                      │                 │
│  │  SSRF风险            │     │  akg-opt             │                 │
│  └──────────────────────┘     │  MLIR文件处理        │                 │
│                               └──────────────────────┘                 │
│                                                                          │
│  ┌──────────────────────┐     ┌──────────────────────┐                 │
│  │   Python 代码执行    │     │   C++ 动态加载        │                 │
│  │  (Critical)          │     │  (Critical)          │                 │
│  │                      │     │                      │                 │
│  │  kernel_verifier.py  │     │  AKGAscendLaunch.cpp │                 │
│  │  exec(impl_code)     │────▶│  dlopen(user_path)   │                 │
│  │                      │     │                      │                 │
│  │  check_torch_code.py │     │  AKGAscendLaunch     │                 │
│  │  exec(stdin_code)    │     │  Runtime.cpp         │                 │
│  │                      │     │                      │                 │
│  │  profiler_utils.py   │     │  CceWrapper.cpp      │                 │
│  │  shell=True          │     │  dlsym符号劫持       │                 │
│  └──────────────────────┘     └──────────────────────┘                 │
│                                                                          │
│  ┌──────────────────────┐     ┌──────────────────────┐                 │
│  │   模板渲染           │     │   JSON解析           │                 │
│  │  (High)              │     │  (Medium)            │                 │
│  │                      │     │                      │                 │
│  │  kernel_verifier     │     │  TranslateTo         │                 │
│  │  Jinja2 Template     │     │  MindsporeDialect    │                 │
│  │                      │     │                      │                 │
│  │  code_checker        │     │  LoadGlobalConfig    │                 │
│  │  agent_base          │     │  DumpShapeInfo       │                 │
│  └──────────────────────┘     └──────────────────────┘                 │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Critical 级漏洞详情

### 1. Remote Code Execution via Worker API (RCE-001)

**位置**: `aikg/python/ai_kernel_generator/worker/server.py:54-89`

**描述**: Worker 服务 API 接收 tar 包并自动执行其中的 Python 脚本，无任何代码过滤或沙箱隔离。

**数据流**:
```
POST /api/v1/verify (UploadFile)
    ↓
package.read() → tarfile.extractall(extract_dir)
    ↓
verify_{op_name}.py 被定位
    ↓
asyncio.create_subprocess_exec(sys.executable, script_path)
```

**攻击向量**:
- 上传包含恶意 Python 脚本的 tar 包
- 脚本自动解压并执行
- 无需任何认证即可触发

**影响**: 远程代码执行，可完全控制 Worker 节点

### 2. Arbitrary Code Execution via exec() (RCE-002)

**位置**: `aikg/python/ai_kernel_generator/core/verifier/kernel_verifier.py:724`

**描述**: 使用 exec() 直接执行 LLM 生成的内核代码

**代码片段**:
```python
compiled = compile(impl_code, '<string>', 'exec')
exec(compiled, self.context)
```

**攻击向量**:
- 通过精心设计的提示词引导 LLM 生成恶意代码
- LLM 输出的代码被直接执行
- 无 AST 验证或代码过滤

**影响**: 代码执行，可能导致系统被控制

### 3. Command Injection via popen() (CMD-001)

**位置**: `akg-mlir/compiler/tools/ascend-linker/ascend-linker.cpp`

**描述**: 使用 popen() 执行 shell 命令，CLI 参数可能包含恶意内容

**代码片段**:
```cpp
FILE* fp = popen(cmd.c_str(), "r");
```

**攻击向量**:
- CLI 参数注入 shell 元字符
- 命令字符串拼接执行

**影响**: 命令注入，可执行任意系统命令

### 4. Code Injection via dlopen() (CODE-001)

**位置**: `akg-mlir/compiler/lib/ExecutionEngine/AscendLaunchRuntime/AKGAscendLaunch.cpp`

**描述**: dlopen() 加载用户提供的共享库路径

**代码片段**:
```cpp
void* handle = dlopen(so_path.data(), RTLD_LAZY);
```

**攻击向量**:
- Python 绑定传入恶意 .so 文件路径
- dlopen 加载并执行恶意共享库

**影响**: 代码注入，可执行任意原生代码

### 5. Shell Command Injection (CMD-002)

**位置**: `aikg/python/ai_kernel_generator/core/verifier/profiler_utils.py:142`

**描述**: 使用 shell=True 执行命令

**代码片段**:
```python
process = subprocess.run(cmd, shell=True, capture_output=True, ...)
```

**攻击向量**:
- script_path 包含 shell 元字符
- 命令注入风险

**影响**: 命令注入

## High 级漏洞详情

### SSRF via Worker Registration (SSRF-001)

**位置**: `aikg/python/ai_kernel_generator/server/app.py:99-117`

**描述**: POST /api/v1/workers/register 接受任意 URL 注册 Worker

**攻击向量**:
- 注册恶意 URL（如内网地址）
- 服务器向该 URL 发送请求
- 可探测内网服务

### Template Injection Potential (TI-001)

**位置**: `aikg/python/ai_kernel_generator/core/verifier/kernel_verifier.py:598`

**描述**: Jinja2 模板渲染用户生成的代码

**攻击向量**:
- LLM 输出包含 Jinja2 模板语法
- 可能触发模板注入

### Arbitrary File Read/Write (FILE-001)

**位置**: `akg-mlir/compiler/tools/ptx-tools/ptx-replace.cpp`

**描述**: PTX 文件处理器进行任意文件读写

**攻击向量**:
- CLI 参数指定任意文件路径
- 正则解析文件内容

### JSON Parsing Vulnerabilities (JSON-001)

**位置**: `akg-mlir/compiler/lib/Target/MindsporeDialect/TranslateToMindsporeDialect.cpp`

**描述**: 解析外部 JSON 文件构建 MLIR IR

**攻击向量**:
- 精心构造的 JSON 文件
- 可能导致解析错误或内存问题

## 高风险模块列表

| 模块 | 路径 | 语言 | 风险等级 | 原因 |
|------|------|------|----------|------|
| ExecutionEngine/AscendLaunchRuntime | akg-mlir/compiler/lib/ExecutionEngine | C++ | Critical | dlopen/dlsym 动态加载 |
| worker | aikg/python/ai_kernel_generator/worker | Python | Critical | 接收并执行用户代码包 |
| core/verifier | aikg/python/ai_kernel_generator/core/verifier | Python | Critical | exec/compile 执行代码 |
| tools/ascend-linker | akg-mlir/compiler/tools/ascend-linker | C++ | Critical | popen 命令执行 |
| tools/ptx-tools | akg-mlir/compiler/tools/ptx-tools | C++ | Critical | 文件读写 |
| server | aikg/python/ai_kernel_generator/server | Python | High | Worker 注册 SSRF |
| Target/MindsporeDialect | akg-mlir/compiler/lib/Target | C++ | High | JSON 解析 |

## 潜在 Sink 函数统计

| Sink 类型 | 语言 | 出现次数 | 严重性 |
|-----------|------|----------|--------|
| exec | Python | 3 | Critical |
| compile | Python | 1 | Critical |
| popen | C++ | 1 | Critical |
| dlopen | C++ | 4 | Critical |
| dlsym | C++ | 5 | High |
| subprocess.run(shell=True) | Python | 3 | High |
| subprocess.Popen | Python | 4 | High |
| os.system | Python | 1 | High |
| Template.render | Python | 10 | Medium |
| ifstream/ofstream | C++ | 15 | Medium |
| getenv | C++ | 8 | Medium |

## 入口点清单

### Web API 入口

| ID | 文件 | 端点 | 风险等级 |
|----|------|------|----------|
| EP-001 | worker/server.py | POST /api/v1/verify | Critical |
| EP-002 | worker/server.py | POST /api/v1/profile | High |
| EP-003 | worker/server.py | POST /api/v1/generate_reference | High |
| EP-004 | server/app.py | POST /api/v1/jobs/submit | High |
| EP-005 | server/app.py | POST /api/v1/workers/register | High |

### CLI 工具入口

| ID | 文件 | 工具名称 | 风险等级 |
|----|------|----------|----------|
| EP-003 | ascend-linker.cpp | ascend-linker | Critical |
| EP-004 | ptx-replace.cpp | ptx-replace | Critical |
| EP-005 | akg-opt.cpp | akg-opt | High |
| EP-006 | akg-translate.cpp | akg-translate | High |
| EP-007 | mindspore-translate.cpp | mindspore-translate | High |

### Python 入口

| ID | 文件 | 入口类型 | 风险等级 |
|----|------|----------|----------|
| EP-009 | cli/cli.py | Typer CLI (akg_cli) | High |
| EP-010 | check_torch_code.py | 脚本入口 | Critical |

## 建议的安全审计重点

### 立即审计 (Critical)

1. **Worker API 代码执行审计**
   - 文件: `worker/server.py`, `core/worker/local_worker.py`
   - 重点: tar 包解压和脚本执行路径

2. **kernel_verifier exec() 审计**
   - 文件: `core/verifier/kernel_verifier.py`
   - 重点: impl_code 参数来源和验证

3. **dlopen 路径验证审计**
   - 文件: `AKGAscendLaunch.cpp`, `AKGAscendLaunchRuntime.cpp`
   - 重点: 路径参数验证和白名单

4. **ascend-linker popen() 审计**
   - 文件: `ascend-linker.cpp`
   - 重点: 命令字符串构建过程

### 高优先级审计 (High)

1. **SSRF 防护审计**
   - 文件: `server/app.py`
   - 重点: Worker URL 注册验证

2. **模板注入审计**
   - 文件: `kernel_verifier.py`, `code_checker.py`
   - 重点: Jinja2 上下文和模板安全性

3. **文件 IO 审计**
   - 文件: `ptx-replace.cpp`
   - 重点: 文件路径验证

### 测试建议

1. 测试上传恶意 tar 包的 RCE 攻击
2. 测试通过 task_desc/op_name 参数注入
3. 测试 SSRF via Worker registration URL
4. 测试 dlopen 恶意 .so 加载
5. 测试 CLI 参数命令注入

## 报告生成信息

- **生成时间**: 2026-04-23T18:57:00Z
- **生成工具**: architecture-agent
- **数据库路径**: scan-results/.context/scan.db
- **相关文件**:
  - project_model.json
  - call_graph.json