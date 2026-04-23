# 漏洞扫描报告 — 已确认漏洞

**项目**: asc-devkit
**扫描时间**: 2026-04-22T09:41:22.109Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 4 | 40.0% |
| POSSIBLE | 3 | 30.0% |
| CONFIRMED | 3 | 30.0% |
| **总计** | **10** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 3 | 100.0% |
| **有效漏洞总计** | **3** | - |
| 误报 (FALSE_POSITIVE) | 0 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SEC-001]** command_injection (High) - `scripts/package/common/py/packer.py:213` @ `exec_pack_cmd` | 置信度: 85
2. **[VULN-SEC-003]** command_injection (High) - `cmake/asc/fwk_modules/util/ascendc_compile_kernel.py:213` @ `ascendc_build` | 置信度: 85
3. **[VULN-DF-001]** path_traversal (High) - `tools/build/asc_pack_kernel/ascendc_pack_kernel.c:75` @ `main` | 置信度: 85

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@undefined` | command_line | - | - | 内核打包工具命令行入口 |
| `ReadFile/WriteFile/GetFileSize@undefined` | file_io | - | - | 文件读写操作 |
| `ElfAddSection/ElfGetSymbolOffset@undefined` | file_io | - | - | ELF 文件处理 |
| `undefined@undefined` | subprocess | - | - | Python 编译脚本调用外部编译器 |


---

## 3. High 漏洞 (3)

### [VULN-SEC-001] command_injection - exec_pack_cmd

**严重性**: High | **CWE**: CWE-78 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `scripts/package/common/py/packer.py:213` @ `exec_pack_cmd`
**模块**: scripts/package

**描述**: packer.py 中 exec_pack_cmd 函数使用 subprocess.run(cmd, shell=True) 执行命令，cmd 由 delivery_dir 和 pack_cmd 参数拼接构建。如果这些参数包含恶意输入（如 '; rm -rf /'），可能导致命令注入攻击。

**漏洞代码** (`scripts/package/common/py/packer.py:213`)

```c
cmd = f'cd {delivery_dir} && {pack_cmd}'
CommLog.cilog_info("package cmd:%s", cmd)
result = subprocess.run(cmd, shell=True, check=False, stdout=PIPE, stderr=STDOUT)
```

**达成路径**

delivery_dir (函数参数) -> cmd 字符串拼接 -> subprocess.run(shell=True) [SINK]

**验证说明**: CLI 参数 delivery_dir 和 pack_cmd 直接进入 subprocess.run(cmd, shell=True)，用户完全控制输入内容，无任何验证或清洗，确认为命令注入漏洞。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-003] command_injection - ascendc_build

**严重性**: High | **CWE**: CWE-78 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `cmake/asc/fwk_modules/util/ascendc_compile_kernel.py:213` @ `ascendc_build`
**模块**: cmake/asc/fwk_modules

**描述**: ascendc_compile_kernel.py 中 ascendc_build 函数使用 os.system(cmd_str.format(...)) 执行编译命令。多个参数（build_opp_path, mkfile, op_impl_py, op_bin_dir, op_cpp_file）来自命令行输入或文件路径，可能被恶意用户控制。

**漏洞代码** (`cmake/asc/fwk_modules/util/ascendc_compile_kernel.py:213`)

```c
cmd_str = ('export HI_PYTHON=python3 && export ASCEND_CUSTOM_OPP_PATH={} && export TILINGKEY_PAR_COMPILE=1'
           '&& make -f {} PY={} OUT={} CPP={}')
if os.system(cmd_str.format(self.build_opp_path, mkfile, self.op_impl_py, op_bin_dir, self.op_cpp_file)) != 0:
```

**达成路径**

args.src_file/args.output_path (CLI参数) -> self.op_cpp_file/op_bin_dir/build_opp_path -> cmd_str.format() -> os.system() [SINK]

**验证说明**: 多个 CLI 参数（src_file、output_path 等）进入 os.system(cmd_str.format(...))，os.path.realpath 不能阻止 shell 注入，确认为命令注入漏洞。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-001] path_traversal - main

**严重性**: High | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `tools/build/asc_pack_kernel/ascendc_pack_kernel.c:75-122` @ `main`
**模块**: tools/build/asc_pack_kernel

**描述**: 命令行参数 argv 直接用作文件路径，攻击者可以通过控制输入路径进行路径遍历攻击，读取或写入任意位置的文件。main 函数接收的 argv[1], argv[2], argv[4] 参数未经验证直接传递给 GetFileSize、ReadFile、WriteFile 函数，这些函数内部使用 fopen/open 打开指定路径的文件。

**漏洞代码** (`tools/build/asc_pack_kernel/ascendc_pack_kernel.c:75-122`)

```c
const char* srcFile = argv[1];
const char* kernelFile = argv[2];
const char* kernelType = argv[3];
const char* dstFile = argv[4];

size_t srcFileSize = GetFileSize(srcFile);
size_t kernelFileSize = GetFileSize(kernelFile);
...
size_t elfAddLen = ReadFile(kernelFile, sec, kernelFileSize);
size_t ssz = ReadFile(srcFile, src, srcFileSize);
...
(void)WriteFile(dstFile, dst, dsz);
```

**达成路径**

argv[1] [SOURCE] (command_line) → main:75 (srcFile) → GetFileSize:26 (fopen) → fopen(filePath, "rb") [SINK]
argv[2] [SOURCE] → main:76 (kernelFile) → ReadFile:44 (open) [SINK]
argv[4] [SOURCE] → main:78 (dstFile) → WriteFile:55 (open) [SINK]

**验证说明**: argv[1]、argv[2]、argv[4] 直接用于 fopen/open 操作，无任何路径验证或清洗，攻击者可使用 ../ 进行路径遍历，确认为路径遍历漏洞。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| cmake/asc/fwk_modules | 0 | 1 | 0 | 0 | 1 |
| scripts/package | 0 | 1 | 0 | 0 | 1 |
| tools/build/asc_pack_kernel | 0 | 1 | 0 | 0 | 1 |
| **合计** | **0** | **3** | **0** | **0** | **3** |

## 5. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-78 | 2 | 66.7% |
| CWE-22 | 1 | 33.3% |
