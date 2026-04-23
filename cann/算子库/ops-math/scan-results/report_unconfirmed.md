# 漏洞扫描报告 — 待确认漏洞

**项目**: Unknown Project
**扫描时间**: 2026-04-22T05:15:26.897Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 14 | 42.4% |
| CONFIRMED | 10 | 30.3% |
| FALSE_POSITIVE | 5 | 15.2% |
| POSSIBLE | 4 | 12.1% |
| **总计** | **33** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 6 | 33.3% |
| Medium | 7 | 38.9% |
| Low | 1 | 5.6% |
| **有效漏洞总计** | **18** | - |
| 误报 (FALSE_POSITIVE) | 5 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-PY-002]** command_injection (High) - `scripts/util/modify_gen_aclnn_static.py:20` @ `main` | 置信度: 70
2. **[VULN-DF-PY-003]** command_injection (High) - `scripts/util/build_opp_kernel_static.py:38` @ `build_kernel` | 置信度: 70
3. **[VULN-SEC-PY-003]** Command Injection (High) - `scripts/util/build_opp_kernel_static.py:94` @ `compile_link_single` | 置信度: 70
4. **[VULN-DF-PY-004]** command_injection (High) - `scripts/package/common/py/packer.py:215` @ `pack` | 置信度: 65
5. **[VULN-SEC-PY-001]** Command Injection (High) - `scripts/package/common/py/packer.py:211` @ `exec_pack_cmd` | 置信度: 65
6. **[VULN-CROSS-003]** integer_overflow (High) - ? @ `?` | 置信度: 65
7. **[VULN-004]** Unsafe Dynamic Access (Medium) - `experimental/math/not_equal/tests/ut/op_kernel/not_equal_data/gen_data.py:17` @ `main` | 置信度: 75
8. **[VULN-DF-PY-005]** unsafe_resource_access (Medium) - `experimental/math/not_equal/tests/ut/op_kernel/not_equal_data/gen_data.py:17` @ `gen_data` | 置信度: 75
9. **[VULN-DF-CPP-002]** insecure_random (Medium) - `random/dsa_random_uniform/op_host/op_api/aclnn_multinomial.cpp:54` @ `aclnnMultinomial` | 置信度: 75
10. **[VULN-SEC-COM-002]** Integer Overflow (Medium) - `random/random_common/op_host/arch35/random_tiling_base.h:57` @ `GetAndCheckOutputSize` | 置信度: 65

---

## 2. 攻击面分析

未找到入口点数据。


---

## 3. High 漏洞 (6)

### [VULN-DF-PY-002] command_injection - main

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-78 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `scripts/util/modify_gen_aclnn_static.py:20-50` @ `main`
**模块**: scripts

**描述**: subprocess.Popen(cmd, shell=True)使用f-string插值，shell元字符可注入命令。路径参数来自CLI或配置，直接拼接进shell命令。

**漏洞代码** (`scripts/util/modify_gen_aclnn_static.py:20-50`)

```c
subprocess.Popen(f"cd {dir_path} && ...", shell=True)
```

**达成路径**

CLI/config [SOURCE] -> f-string interpolation -> subprocess.Popen(cmd, shell=True) [SINK]

**验证说明**: shell_exec使用bash -c包装器，shell=False但f-string中的路径参数仍可能注入shell元字符。aclnn_cpp路径来自文件遍历。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-DF-PY-003] command_injection - build_kernel

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-78 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `scripts/util/build_opp_kernel_static.py:38-136` @ `build_kernel`
**模块**: scripts

**描述**: 多处subprocess.Popen(cmd, shell=True)调用存在shell注入风险。f-string拼接路径参数到shell命令，无验证。

**漏洞代码** (`scripts/util/build_opp_kernel_static.py:38-136`)

```c
subprocess.Popen(f"cd {dir_path} && make ...", shell=True)
```

**达成路径**

CLI/config [SOURCE] -> f-string interpolation -> subprocess.Popen(cmd, shell=True) [SINK]

**验证说明**: build_opp_kernel_static.py多处shell_exec使用bash -c包装器，dir_path和file_name参数可能被shell元字符注入。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-PY-003] Command Injection - compile_link_single

**严重性**: High（原评估: critical → 验证后: High） | **CWE**: CWE-78 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `scripts/util/build_opp_kernel_static.py:94-107` @ `compile_link_single`
**模块**: scripts

**描述**: Shell injection via f-string interpolation in shell_exec() function. Multiple calls use bash -c with f-strings containing file paths (dir_path, aclnn_cpp). If file paths contain shell metacharacters like '; rm -rf /', arbitrary commands can be executed.

**漏洞代码** (`scripts/util/build_opp_kernel_static.py:94-107`)

```c
shell_exec(["bash", "-c", f"cd {dir_path} && objcopy --input-target binary ...
{file_name} {file_o}"], shell=False)
```

**达成路径**

file_path -> dir_path -> f-string -> bash -c -> shell command

**验证说明**: build_opp_kernel_static.py shell_exec多处bash -c f-string，路径参数可被shell元字符注入。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-DF-PY-004] command_injection - pack

**严重性**: High | **CWE**: CWE-78 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `scripts/package/common/py/packer.py:215` @ `pack`
**模块**: scripts

**描述**: subprocess.run(cmd, shell=True)处理用户提供的路径。路径参数可能包含shell元字符导致命令注入。

**漏洞代码** (`scripts/package/common/py/packer.py:215`)

```c
subprocess.run(cmd, shell=True)
```

**达成路径**

用户路径 [SOURCE] -> subprocess.run(cmd, shell=True) [SINK]

**验证说明**: subprocess.run(cmd, shell=True)处理delivery_dir参数，f-string拼接进shell命令，可能注入命令。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-PY-001] Command Injection - exec_pack_cmd

**严重性**: High（原评估: high → 验证后: High） | **CWE**: CWE-78 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `scripts/package/common/py/packer.py:211-215` @ `exec_pack_cmd`
**模块**: scripts

**描述**: Shell injection via subprocess.run(cmd, shell=True) with f-string interpolation of delivery_dir and pack_cmd. delivery_dir comes from function parameter, pack_cmd from compose_makeself_command() which builds commands from user-controlled package attributes.

**漏洞代码** (`scripts/package/common/py/packer.py:211-215`)

```c
cmd = f'cd {delivery_dir} && {pack_cmd}'
result = subprocess.run(cmd, shell=True, check=False, stdout=PIPE, stderr=STDOUT)
```

**达成路径**

delivery_dir (user param) -> f-string cmd -> subprocess.run(shell=True) -> shell command execution

**验证说明**: packer.py exec_pack_cmd使用subprocess.run(shell=True)，delivery_dir和pack_cmd拼接进命令字符串。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-CROSS-003] integer_overflow - unknown

**严重性**: High | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `?:?` @ `?`
**模块**: cross_module
**跨模块**: common → math → conversion → experimental

**描述**: 跨模块整数溢出攻击链: GetPartShapeSize(op_util.h) → 形状计算 → 内存分配。所有模块的算子入口点都依赖此函数，缺少溢出检查导致内存分配风险。

**达成路径**

common[op_util.h:GetPartShapeSize] → math/conversion/experimental[算子调用] → executor->AllocTensor

**验证说明**: GetPartShapeSize(op_util.h)无溢出检查进行int64_t乘法，所有模块算子入口点依赖此函数进行形状计算，可能导致内存分配失败或缓冲区溢出。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (7)

### [VULN-004] Unsafe Dynamic Access - main

**严重性**: Medium（原评估: medium → 验证后: Medium） | **CWE**: CWE-669 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: architecture

**位置**: `experimental/math/not_equal/tests/ut/op_kernel/not_equal_data/gen_data.py:17-20` @ `main`
**模块**: experimental

**描述**: getattr(torch, x1_type) accesses torch module attributes from CLI input without whitelist

**漏洞代码** (`experimental/math/not_equal/tests/ut/op_kernel/not_equal_data/gen_data.py:17-20`)

```c
getattr(torch, x1_type)
```

**达成路径**

sys.argv[2] -> getattr(torch, type) -> internal attribute access

**验证说明**: experimental/math gen_data.py getattr(torch, x1_type)从CLI输入访问torch属性，无白名单限制。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-PY-005] unsafe_resource_access - gen_data

**严重性**: Medium | **CWE**: CWE-669 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `experimental/math/not_equal/tests/ut/op_kernel/not_equal_data/gen_data.py:17-20` @ `gen_data`
**模块**: scripts

**描述**: getattr(torch, x1_type)从CLI输入访问torch模块属性。动态属性访问可能导致访问不预期的属性或方法。

**漏洞代码** (`experimental/math/not_equal/tests/ut/op_kernel/not_equal_data/gen_data.py:17-20`)

```c
x1_type = sys.argv[...]; getattr(torch, x1_type)
```

**达成路径**

sys.argv [SOURCE] -> getattr(torch, x1_type) [SINK]

**验证说明**: getattr(torch, x1_type)从CLI输入访问torch模块属性，可访问任意torch属性。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-CPP-002] insecure_random - aclnnMultinomial

**严重性**: Medium | **CWE**: CWE-338 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `random/dsa_random_uniform/op_host/op_api/aclnn_multinomial.cpp:54-55` @ `aclnnMultinomial`
**模块**: random

**描述**: Multinomial采样接收int64_t seed参数，种子可预测时输出可预测。确定性PRNG - 相同种子产生相同输出。

**漏洞代码** (`random/dsa_random_uniform/op_host/op_api/aclnn_multinomial.cpp:54-55`)

```c
int64_t seed = ctx->GetInput<Tensor>(3).GetValue<int64_t>()
```

**达成路径**

seed_param [SOURCE] -> MultinomialWithReplacement() -> Philox RNG [SINK]

**验证说明**: aclnnMultinomial接收int64_t seed参数，用户提供的seed完全决定输出。确定性PRNG影响安全应用采样可预测性。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-COM-002] Integer Overflow - GetAndCheckOutputSize

**严重性**: Medium（原评估: medium → 验证后: Medium） | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `random/random_common/op_host/arch35/random_tiling_base.h:57-61` @ `GetAndCheckOutputSize`
**模块**: common
**跨模块**: random → common

**描述**: GetAndCheckOutputSize() calculates shapeSize by multiplying all dimensions without overflow checks. For large tensors, shapeSize multiplication could overflow int64_t, causing incorrect size calculations that lead to memory allocation failures or buffer overflows.

**漏洞代码** (`random/random_common/op_host/arch35/random_tiling_base.h:57-61`)

```c
shapeSize = 1;
for (uint32_t idx = 0; idx < shapeRank; idx++) {
    shapeSize *= static_cast<int64_t>(constShape.GetDim(idx));
}
```

**达成路径**

shape dimensions -> iterative multiplication -> potential int64 overflow -> memory size mismatch

**验证说明**: GetAndCheckOutputSize()计算shapeSize时进行int64_t乘法无溢出检查，大张量可能导致整数溢出。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-PY-006] unsafe_resource_access - run_test

**严重性**: Medium | **CWE**: CWE-669 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `scripts/torch_extension/torch_extension_ut_runner.py:43-44` @ `run_test`
**模块**: scripts

**描述**: importlib.util.spec_from_file_location()动态加载Python文件。动态模块加载可能导致加载恶意代码。

**漏洞代码** (`scripts/torch_extension/torch_extension_ut_runner.py:43-44`)

```c
spec = importlib.util.spec_from_file_location(module_name, file_path)
```

**达成路径**

file_path [SOURCE] -> importlib.util.spec_from_file_location() [SINK]

**验证说明**: torch_extension_ut_runner.py importlib动态加载YAML配置指定的Python文件，可加载恶意代码。yaml.safe_load安全但路径可控。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-DF-PY-007] input_validation - parse_ini

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `scripts/kernel/binary_script/parser_ini.py:52-73` @ `parse_ini`
**模块**: scripts

**描述**: INI文件解析无输入验证，可能解析恶意配置。缺少schema验证和大小限制。

**漏洞代码** (`scripts/kernel/binary_script/parser_ini.py:52-73`)

```c
config.read(file_path)
```

**达成路径**

ini_file [SOURCE] -> ConfigParser.read() -> config values [SINK]

**验证说明**: parser_ini.py INI文件解析缺少schema验证，无大小限制。配置文件解析风险较低。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-CROSS-004] input_validation - unknown

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `?:?` @ `?`
**模块**: cross_module
**跨模块**: common → math → conversion → experimental → random

**描述**: 跨模块输入验证缺口: OP_CHECK_*宏仅检查指针非空、形状相等、维度上限，缺少张量数据内容验证、内存大小上限验证、整数溢出检查。影响所有300个算子入口点。

**达成路径**

用户API调用 → op_api层[OP_CHECK_*验证] → 缺口[值范围/内存上限/溢出] → op_kernel层

**验证说明**: OP_CHECK_*宏仅检查指针非空、形状相等、维度上限，缺少张量数据内容验证、内存大小上限、整数溢出检查。影响所有300个算子入口点。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -10 | context: 0 | cross_file: 0

---

## 5. Low 漏洞 (1)

### [VULN-DF-PY-008] input_validation - convert

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `scripts/util/parse_ini_to_json.py:85-115` @ `convert`
**模块**: scripts

**描述**: JSON/INI解析缺少schema验证和大小限制。配置文件解析无输入验证。

**漏洞代码** (`scripts/util/parse_ini_to_json.py:85-115`)

```c
json.load(f); config.read(file)
```

**达成路径**

config_file [SOURCE] -> json.load()/ConfigParser.read() [SINK]

**验证说明**: parse_ini_to_json.py JSON/INI解析缺少schema验证，有10MB大小检查但无内容验证。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -5 | context: 0 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| common | 0 | 0 | 1 | 0 | 1 |
| cross_module | 0 | 1 | 1 | 0 | 2 |
| experimental | 0 | 0 | 1 | 0 | 1 |
| random | 0 | 0 | 1 | 0 | 1 |
| scripts | 0 | 5 | 3 | 1 | 9 |
| **合计** | **0** | **6** | **7** | **1** | **14** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-78 | 5 | 27.8% |
| CWE-20 | 4 | 22.2% |
| CWE-190 | 4 | 22.2% |
| CWE-669 | 3 | 16.7% |
| CWE-758 | 1 | 5.6% |
| CWE-338 | 1 | 5.6% |
