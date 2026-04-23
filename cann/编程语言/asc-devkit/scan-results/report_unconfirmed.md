# 漏洞扫描报告 — 待确认漏洞

**项目**: asc-devkit
**扫描时间**: 2026-04-22T09:41:22.109Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

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
| High | 1 | 14.3% |
| Medium | 5 | 71.4% |
| Low | 1 | 14.3% |
| **有效漏洞总计** | **7** | - |
| 误报 (FALSE_POSITIVE) | 0 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SEC-002]** command_injection (High) - `cmake/asc/fwk_modules/util/compile_ascendc_all_ops_so.py:126` @ `run_compile_cmd` | 置信度: 65
2. **[VULN-DF-002]** path_traversal (Medium) - `tools/build/asc_op_compile_base/adapter/compile_op.py:218` @ `_json_post_process` | 置信度: 65
3. **[VULN-DF-003]** path_traversal (Medium) - `tools/build/asc_op_compile_base/adapter/compile_op.py:137` @ `_json_except_info` | 置信度: 65
4. **[VULN-DF-004]** command_injection (Medium) - `tools/build/asc_op_compile_base/adapter/ascendc_compile_base.py:258` @ `compile_multi_tilingkey` | 置信度: 60
5. **[VULN-DF-005]** path_traversal (Medium) - `tools/build/asc_op_compile_base/adapter/super_kernel_op_infos.py:822` @ `split_o_in_super_kernel` | 置信度: 50
6. **[VULN-DF-007]** path_traversal (Medium) - `tools/build/asc_op_compile_base/adapter/get_op_tiling.py:1587` @ `get_tiling_info_online_build` | 置信度: 50
7. **[VULN-DF-006]** integer_overflow (Low) - `tools/build/asc_pack_kernel/ascendc_pack_kernel.c:112` @ `main` | 置信度: 55

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@undefined` | command_line | - | - | 内核打包工具命令行入口 |
| `ReadFile/WriteFile/GetFileSize@undefined` | file_io | - | - | 文件读写操作 |
| `ElfAddSection/ElfGetSymbolOffset@undefined` | file_io | - | - | ELF 文件处理 |
| `undefined@undefined` | subprocess | - | - | Python 编译脚本调用外部编译器 |


---

## 3. High 漏洞 (1)

### [VULN-SEC-002] command_injection - run_compile_cmd

**严重性**: High | **CWE**: CWE-78 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `cmake/asc/fwk_modules/util/compile_ascendc_all_ops_so.py:126-127` @ `run_compile_cmd`
**模块**: cmake/asc/fwk_modules

**描述**: compile_ascendc_all_ops_so.py 中 run_compile_cmd 函数使用 os.system(cmd) 执行 make 命令。mkfile 来自命令行参数 args.output_dir，攻击者可通过控制 output_dir 参数注入恶意命令。

**漏洞代码** (`cmake/asc/fwk_modules/util/compile_ascendc_all_ops_so.py:126-127`)

```c
cmd = f"make -f {mkfile} -j{parallel_compile_job}"
ret = os.system(cmd)
```

**达成路径**

args.output_dir (CLI参数) -> mkfile -> cmd 字符串拼接 -> os.system() [SINK]

**验证说明**: CLI 参数 output_dir 进入 os.system(cmd)，但有 mkfile 存在性检查部分缓解。用户需要使目标路径存在才能执行，但仍存在命令注入风险。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (5)

### [VULN-DF-002] path_traversal - _json_post_process

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `tools/build/asc_op_compile_base/adapter/compile_op.py:218-222` @ `_json_post_process`
**模块**: tools/build/asc_op_compile_base

**描述**: 用户提供的 kernel_name（来自 op_info.kernel_name）直接用于构建文件路径，攻击者可以通过控制 kernel_name 值（如包含 ../ 或绝对路径）在任意位置创建或读取 JSON 文件。compile_info.kernel_name 来自 op_info.kernel_name，然后被用于构建 json_path 和 obj_path。

**漏洞代码** (`tools/build/asc_op_compile_base/adapter/compile_op.py:218-222`)

```c
kernel_meta_path = CommonUtility.get_kernel_meta_dir()
json_path = os.path.join(kernel_meta_path, compile_info.kernel_name + '.json')
obj_path = os.path.join(kernel_meta_path, compile_info.kernel_name + '.o')
...
with open(json_path, 'r') as fd:
    js = json.load(fd)
```

**达成路径**

op_info.kernel_name [SOURCE] (user input via OpInfo namedtuple) → compile_op.py:1307 (compile_info.kernel_name = op_info.kernel_name) → compile_op.py:218 (json_path = os.path.join(..., kernel_name + '.json')) → open(json_path, 'r') [SINK]

**验证说明**: kernel_name 来自 op_info 配置，直接用于构建文件路径 json_path 和 obj_path，无验证，存在路径遍历风险。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-003] path_traversal - _json_except_info

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `tools/build/asc_op_compile_base/adapter/compile_op.py:137-141` @ `_json_except_info`
**模块**: tools/build/asc_op_compile_base

**描述**: sub_op.get("json_path") 直接用作文件打开路径，该路径来自 super_kernel_info.op_list 列表中的元素，如果 op_list 由外部用户提供，攻击者可以通过控制 json_path 进行路径遍历攻击。

**漏洞代码** (`tools/build/asc_op_compile_base/adapter/compile_op.py:137-141`)

```c
for sub_op in compile_info.super_kernel_info["op_list"]:
    sub_json_path = sub_op.get("json_path")
    ...
    with open(sub_json_path, 'r') as fd:
        sub_operater_infos = json.load(fd)
```

**达成路径**

compile_info.super_kernel_info.op_list[].json_path [SOURCE] (user input via super_kernel_info) → compile_op.py:137 (sub_json_path = sub_op.get("json_path")) → open(sub_json_path, 'r') [SINK]

**验证说明**: json_path 来自 super_kernel_info.op_list 配置，直接用于 open()，无验证，存在路径遍历风险。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-004] command_injection - compile_multi_tilingkey

**严重性**: Medium | **CWE**: CWE-78 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `tools/build/asc_op_compile_base/adapter/ascendc_compile_base.py:258-273` @ `compile_multi_tilingkey`
**模块**: tools/build/asc_op_compile_base

**描述**: os.system 调用使用字符串拼接执行命令，虽然主要参数来自内部生成，但 file_name 路径可能通过 kernel_name 间接被污染。如果 kernel_name 包含特殊字符（如分号、反引号），可能导致命令注入。cmd_str 包含 'tee -a file_name'，file_name 通过 get_build_file_name(cmds_list[0], ...) 生成。

**漏洞代码** (`tools/build/asc_op_compile_base/adapter/ascendc_compile_base.py:258-273`)

```c
cmd = ['make', '-f', mk_file, '-j', f'{ascendc_self_par_job_num}']
cmd_str = ' '.join(cmd)
...
if global_var_storage.get_variable("ascendc_enable_build_log") is True:
    ...
    cmd.append('tee -a')
    cmd.append(file_name)
    cmd_str = ' '.join(cmd)
ret = os.system(f'{cmd_str} > /dev/null')
```

**达成路径**

cmds_list[0] → get_build_file_name() → file_name → cmd.append(file_name) → cmd_str → os.system(cmd_str) [SINK]

**验证说明**: os.system(cmd_str) 执行编译命令，file_name 间接来自 kernel_name，可能存在命令注入风险。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-005] path_traversal - split_o_in_super_kernel

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-22 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `tools/build/asc_op_compile_base/adapter/super_kernel_op_infos.py:822-842` @ `split_o_in_super_kernel`
**模块**: tools/build/asc_op_compile_base

**描述**: 用户可控的 bin_path 和 kernel_name 用于构建 subprocess 命令参数。origin_kernel_name 来自 super_kernel 配置，如果包含路径字符，可能导致路径遍历。subprocess.run 使用列表形式，直接的命令注入风险较低，但路径遍历风险仍然存在。

**漏洞代码** (`tools/build/asc_op_compile_base/adapter/super_kernel_op_infos.py:822-842`)

```c
def split_o_in_super_kernel(self, orign_bin_path, origin_kernel_name, i):
    filename = os.path.basename(orign_bin_path)
    kernel_meta_dir = CommonUtility.get_kernel_meta_dir()
    new_bin_path = os.path.join(kernel_meta_dir, filename[:-2] + f"_split{i}.o")
    cmds = ['cp', '-rfL', f'{orign_bin_path}', f'{new_bin_path}']
    subprocess.run(cmds)
    cmds = ['llvm-objcopy', f'--redefine-sym={origin_kernel_name}={new_kernel_name}', f'{new_bin_path}']
    subprocess.run(cmds)
```

**达成路径**

orign_bin_path [SOURCE] (from super_kernel op_list) → subprocess.run(['cp', '-rfL', orign_bin_path, ...]) [SINK]
origin_kernel_name [SOURCE] → llvm-objcopy --redefine-sym argument [SINK]

**验证说明**: 使用列表形式 subprocess.run（无 shell 注入风险），但 orign_bin_path 和 origin_kernel_name 来自配置，仍存在路径遍历风险。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-DF-007] path_traversal - get_tiling_info_online_build

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-22 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `tools/build/asc_op_compile_base/adapter/get_op_tiling.py:1587-1594` @ `get_tiling_info_online_build`
**模块**: tools/build/asc_op_compile_base

**描述**: subprocess.run 使用用户提供的 isolate_json_path 作为命令参数。op_info.op_type 来自用户输入（算子类型），用于构建 isolate_json_path 文件名。如果 op_type 包含路径遍历字符（如 ../），可能导致在任意位置创建文件。

**漏洞代码** (`tools/build/asc_op_compile_base/adapter/get_op_tiling.py:1587-1594`)

```c
isolate_json_path = os.path.join(kernel_meta_path, op_info.op_type + f"_isolate_tiling_{os.getpid()}.json")
with open(isolate_json_path, 'w', encoding="utf-8") as f:
    f.write(isolate_json_str)
...
result = subprocess.run(["python3", isolate_python_path, op_info.op_type, isolate_json_path])
```

**达成路径**

op_info.op_type [SOURCE] (user input) → isolate_json_path = os.path.join(..., op_info.op_type + ...) → open(isolate_json_path, 'w') [SINK] → subprocess.run([... isolate_json_path])

**验证说明**: op_info.op_type 用于构建文件名，使用列表形式 subprocess.run（无 shell 注入），但 op_type 可包含 ../ 导致路径遍历。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

## 5. Low 漏洞 (1)

### [VULN-DF-006] integer_overflow - main

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `tools/build/asc_pack_kernel/ascendc_pack_kernel.c:112-119` @ `main`
**模块**: tools/build/asc_pack_kernel

**描述**: strtol 转换 argv[3] 到 uint32_t type，但没有检查 strtol 的错误返回。如果 kernelType 是非数字字符串，strtol 返回 0，可能意外匹配 ELF_TYPE_ELF 类型。后续代码有 type >= ELF_TYPE_MAX 检查，但 strtol 的错误情况未被处理。

**漏洞代码** (`tools/build/asc_pack_kernel/ascendc_pack_kernel.c:112-119`)

```c
uint32_t type = (uint32_t)strtol(kernelType, NULL, 10);
if (type >= ELF_TYPE_MAX) {
    printf("[Error] sec_name type: %s is error!\n", kernelType);
    ...
    return 1;
}
```

**达成路径**

argv[3] (kernelType) [SOURCE] → strtol(kernelType, NULL, 10) → type → if(type >= ELF_TYPE_MAX) check

**验证说明**: strtol 缺少错误处理，但后续有 type >= ELF_TYPE_MAX 边界检查。非数字输入返回 0，会通过检查正常执行，主要是代码质量问题而非安全漏洞。

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| cmake/asc/fwk_modules | 0 | 1 | 0 | 0 | 1 |
| tools/build/asc_op_compile_base | 0 | 0 | 5 | 0 | 5 |
| tools/build/asc_pack_kernel | 0 | 0 | 0 | 1 | 1 |
| **合计** | **0** | **1** | **5** | **1** | **7** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-22 | 4 | 57.1% |
| CWE-78 | 2 | 28.6% |
| CWE-190 | 1 | 14.3% |
