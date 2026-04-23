# 漏洞扫描报告 - 待确认漏洞

**项目**: asc-tools (AscendC 开发工具框架)
**扫描时间**: 2026-04-23T01:53:50.828Z
**报告范围**: LIKELY / POSSIBLE 状态漏洞

---

## 执行摘要

本报告包含 **5 个待确认漏洞**，包括 2 个 High 级别、2 个 Medium 级别和 1 个 Low 级别漏洞。这些漏洞需要进一步人工验证以确定其真实性和修复优先级。

### 关键发现

| 漏洞类型 | 数量 | 最高严重性 |
|----------|------|------------|
| 命令注入 (CWE-78) | 2 | High |
| 输入验证缺失 (CWE-20) | 1 | High |
| 缓冲区越界读取 (CWE-125) | 2 | Medium |

**风险评估**:
- 1 个命令注入漏洞使用 `os.system()` 执行命令，风险较高但存在路径规范化缓解
- 2 个缓冲区越界漏洞位于 ELF 解析器中，需要恶意 ELF 文件才能触发
- 输入验证缺失漏洞影响 ELF 文件解析安全性

### 建议行动

| 优先级 | 漏洞ID | 类型 | 建议行动 |
|--------|--------|------|----------|
| P1 | VULN-DF-PY-003 | 命令注入 | 人工验证 `os.system()` 调用安全性 |
| P1 | VULN-DF-CPP-001 | 输入验证 | 添加 ELF magic 验证 |
| P2 | VULN-DF-CPP-003 | 缓冲区越界 | 添加 `sh_name` 边界检查 |
| P2 | VULN-DF-CPP-002 | 缓冲区越界 | 修复指针算术 bug |
| P3 | VULN-DF-PY-004 | 命令注入 | 使用列表参数已降低风险 |

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 3 | 30.0% |
| FALSE_POSITIVE | 3 | 30.0% |
| POSSIBLE | 2 | 20.0% |
| CONFIRMED | 2 | 20.0% |
| **总计** | **10** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 2 | 40.0% |
| Medium | 2 | 40.0% |
| Low | 1 | 20.0% |
| **有效漏洞总计** | **5** | - |
| 误报 (FALSE_POSITIVE) | 3 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-PY-003]** command_injection (High) - `utils/templates/op_project_templates/ascendc/common/util/ascendc_compile_kernel.py:156` @ `CompileKernel.ascendc_build` | 置信度: 70
2. **[VULN-DF-CPP-001]** input_validation (High) - `cpudebug/include/kernel_elf_parser.h:190` @ `ParseElfHeader` | 置信度: 65
3. **[VULN-DF-CPP-003]** buffer_overread (Medium) - `cpudebug/include/kernel_elf_parser.h:328` @ `ParseKernelSections` | 置信度: 70
4. **[VULN-DF-CPP-002]** buffer_overread (Medium) - `cpudebug/include/kernel_elf_parser.h:255` @ `GetSectionHeader` | 置信度: 55
5. **[VULN-DF-PY-004]** command_injection (Low) - `utils/msobjdump/msobjdump/utils.py:47` @ `get_section_headers_in_file/get_symbols_in_file/extract_aicore_binary_from_elf` | 置信度: 40

---

## 2. 攻击面分析

未找到入口点数据。


---

## 3. High 漏洞 (2)

### [VULN-DF-PY-003] command_injection - CompileKernel.ascendc_build

**严重性**: High | **CWE**: CWE-78 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `utils/templates/op_project_templates/ascendc/common/util/ascendc_compile_kernel.py:156-162` @ `CompileKernel.ascendc_build`
**模块**: op_project_templates

**描述**: ascendc_build method uses os.system(cmd_str.format(...)) where cmd_str contains shell commands with format placeholders for paths. Paths like build_opp_path, mkfile, op_impl_py, op_cpp_file come from CLI args or file paths. If paths contain shell metacharacters, can inject arbitrary commands.

**漏洞代码** (`utils/templates/op_project_templates/ascendc/common/util/ascendc_compile_kernel.py:156-162`)

```c
cmd_str = ('export HI_PYTHON=python3 && export ASCEND_CUSTOM_OPP_PATH={} && ...')
os.system(cmd_str.format(self.build_opp_path, mkfile, self.op_impl_py, op_bin_dir, self.op_cpp_file))
```

**达成路径**

args_parse [SOURCE - CLI args]
 -> CompileKernel.__init__ (sets paths)
 -> ascendc_build [SINK - os.system injection]

**验证说明**: op_cpp_file from args.src_file (CLI), but processed through os.path.realpath which normalizes path. build_opp_path is constructed internally. Partial control via realpath-normalized paths, but shell metacharacters may still work. os.system() is dangerous.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: -5 | cross_file: 0

---

### [VULN-DF-CPP-001] input_validation - ParseElfHeader

**严重性**: High | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cpudebug/include/kernel_elf_parser.h:190-235` @ `ParseElfHeader`
**模块**: cpudebug

**描述**: ParseElfHeader function receives external ELF binary data but does not validate the ELF magic number (EI_MAG0-3 should be 0x7f, 'E', 'L', 'F'). Data comes from aclrtBinaryLoadFromData API which accepts external buffer. Attacker could provide malformed ELF data without magic validation, leading to undefined behavior when parsing.

**漏洞代码** (`cpudebug/include/kernel_elf_parser.h:190-235`)

```c
inline Elf64_Ehdr ParseElfHeader(const uint8_t* const elfData, size_t dataSize)
{
    if (dataSize < sizeof(Elf64_Ehdr)) {
        throw std::invalid_argument(...);
    }
    switch (elfData[EI_DATA]) { ... }
    // No magic number validation before proceeding
```

**达成路径**

aclrtBinaryLoadFromData (ascendc_acl_stub.cpp:300) [SOURCE]
 -> RegisterKernelElf (kernel_elf_parser.h:349)
 -> ParseElfHeader (kernel_elf_parser.h:190) [SINK - Missing validation]

**验证说明**: aclrtBinaryLoadFromData API accepts external ELF data buffer. ParseElfHeader checks dataSize and EI_CLASS but skips ELF magic validation (EI_MAG0-3 should be 0x7f,'E','L','F'). Malformed ELF without magic could cause undefined behavior in subsequent parsing.

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: -10 | context: -5 | cross_file: 0

---

## 4. Medium 漏洞 (2)

### [VULN-DF-CPP-003] buffer_overread - ParseKernelSections

**严重性**: Medium | **CWE**: CWE-125 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cpudebug/include/kernel_elf_parser.h:328-335` @ `ParseKernelSections`
**模块**: cpudebug

**描述**: ParseKernelSections reads strings from shStrTab using reinterpret_cast with sh_name as index. If malicious ELF sets sh_name to value exceeding sh_size, could read uninitialized memory or cause crash.

**漏洞代码** (`cpudebug/include/kernel_elf_parser.h:328-335`)

```c
const uint8_t* shStrTab = elfData + shStrTabHdr.sh_offset;
std::string sectionName(reinterpret_cast<const char*>(shStrTab) + shdr.sh_name);  // No bounds check on sh_name
```

**达成路径**

RegisterKernelElf -> ParseKernelSections (line 335) [SINK - Unbounded string read]

**验证说明**: sh_name used as offset to access shStrTab without bounds check. shStrTabHdr.sh_offset+sh_size bounds checked, but sh_name value not validated against sh_size. Malicious ELF with large sh_name could read beyond string table boundary.

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: -5 | context: -5 | cross_file: 0

---

### [VULN-DF-CPP-002] buffer_overread - GetSectionHeader

**严重性**: Medium | **CWE**: CWE-125 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `cpudebug/include/kernel_elf_parser.h:255` @ `GetSectionHeader`
**模块**: cpudebug

**描述**: GetSectionHeader function has a bug at line 255: reads 4 bytes for sh_size but increments pointer by 8 bytes. This causes subsequent fields to be read from wrong offsets. Malicious ELF could exploit this inconsistency.

**漏洞代码** (`cpudebug/include/kernel_elf_parser.h:255`)

```c
shdr.sh_size = GetByte(data, 4); data += 8;  // BUG: read 4 but skip 8
```

**达成路径**

RegisterKernelElf -> GetSectionHeader (line 255) [SINK - Incorrect pointer arithmetic]

**验证说明**: Implementation bug: sh_size read 4 bytes (GetByte(data,4)) but pointer advances 8 bytes. For 64-bit ELF, sh_size should be 8 bytes. This misalignment causes subsequent field reads from wrong offsets. Limited exploitation potential.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: -10 | cross_file: 0

---

## 5. Low 漏洞 (1)

### [VULN-DF-PY-004] command_injection - get_section_headers_in_file/get_symbols_in_file/extract_aicore_binary_from_elf

**严重性**: Low | **CWE**: CWE-78 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `utils/msobjdump/msobjdump/utils.py:47-67` @ `get_section_headers_in_file/get_symbols_in_file/extract_aicore_binary_from_elf`
**模块**: msobjdump

**描述**: utils.py functions use subprocess.run with list args (no shell=True), which is safer. However, file_name comes from user CLI input. While direct shell injection is prevented, specially crafted filenames could potentially affect tool behavior (e.g., readelf parameters). Risk is lower due to list-based invocation.

**漏洞代码** (`utils/msobjdump/msobjdump/utils.py:47-67`)

```c
subprocess.run(['readelf', '-SW', file_name], capture_output=True, text=True)
subprocess.run(['llvm-objcopy', '-O', 'binary', '--only-section=.aicore_binary', input_file, output_file])
```

**达成路径**

msobjdump_main.py args_parse [SOURCE]
 -> ObjDump -> utils.py [SINK - subprocess with list args]

**验证说明**: Uses subprocess.run with list args (no shell=True), which prevents shell metacharacter injection. file_name from CLI args. Only risk is specially crafted filenames affecting readelf/llvm-objcopy behavior (argument injection), but this is minimal.

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: -15 | context: -5 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| cpudebug | 0 | 1 | 2 | 0 | 3 |
| msobjdump | 0 | 0 | 0 | 1 | 1 |
| op_project_templates | 0 | 1 | 0 | 0 | 1 |
| **合计** | **0** | **2** | **2** | **1** | **5** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-78 | 2 | 40.0% |
| CWE-125 | 2 | 40.0% |
| CWE-20 | 1 | 20.0% |
