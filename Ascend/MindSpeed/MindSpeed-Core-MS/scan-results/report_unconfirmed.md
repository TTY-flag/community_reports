# 漏洞扫描报告 — 待确认漏洞

**项目**: MindSpeed-Core-MS
**扫描时间**: 2026-04-20T12:00:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| CONFIRMED | 9 | 37.5% |
| LIKELY | 8 | 33.3% |
| FALSE_POSITIVE | 5 | 20.8% |
| POSSIBLE | 2 | 8.3% |
| **总计** | **24** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 7 | 70.0% |
| Medium | 2 | 20.0% |
| **有效漏洞总计** | **10** | - |
| 误报 (FALSE_POSITIVE) | 5 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-003-94]** Code Injection via Statement Parsing (High) - `tools/convert/patch_merge/modules/patch_func_router.py:62` @ `_merged_branch_builder` | 置信度: 75
2. **[VULN-007-94]** Code Injection via Factory Class (High) - `tools/convert/patch_merge/modules/patch_class_add_factory.py:85` @ `_merged_branch_builder` | 置信度: 75
3. **[VULN-008-94]** Code Injection via Wrapper (High) - `tools/convert/patch_merge/modules/patch_wrapper_router.py:130` @ `_build_inner_wrapped_call` | 置信度: 75
4. **[tools_load_weights-CWE502-indirect-pickle-001]** Indirect Pickle Deserialization (High) - `tools/load_ms_weights_to_pt/checkpointing.py:3` @ `load_wrapper` | 置信度: 75
5. **[VULN-004-94]** Dynamic Import Execution (High) - `tools/convert/patch_merge/modules/merge.py:186` @ `parse_path` | 置信度: 70
6. **[tests-serialize-unsafe-pickle-001]** Deserialization (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-Core-MS/tools/load_ms_weights_to_pt/serialization.py:508` @ `_load` | 置信度: 65
7. **[tests-checkpointing-unsafe-import-004]** Unsafe Dynamic Import (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-Core-MS/tools/load_ms_weights_to_pt/checkpointing.py:1` @ `load_wrapper` | 置信度: 60
8. **[tools_load_weights-CWE22-path-traversal-001]** Path Traversal (Medium) - `tools/load_ms_weights_to_pt/transfer.py:16` @ `copy_weights_transfer_tool_file` | 置信度: 55
9. **[tools_load_weights-CWE73-file-write-001]** Arbitrary File Write (Medium) - `tools/load_ms_weights_to_pt/transfer.py:32` @ `patch_torch_load` | 置信度: 50
10. **[1297a76b-bd96-451d-9cc2-b7425589e5bd]** Path Traversal - Arbitrary File Read (LOW) - `tools/transfer.py:32` @ `convert_general_rules` | 置信度: 70

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@tools/convert/convert.py` | cmdline | untrusted_local | CLI工具入口，接收用户通过命令行传入的--path_to_change参数，该路径指向需要转换的代码目录或文件。本地用户可以控制此参数，可能传入恶意路径或包含恶意代码的文件。 | 代码转换工具CLI入口，处理PyTorch到MSAdapter的API映射 |
| `main@tools/transfer.py` | cmdline | untrusted_local | CLI工具入口，接收多个路径参数（megatron_path、mindspeed_path、mindspeed_llm_path等），这些路径由用户在命令行指定。本地用户可以控制这些参数，可能传入恶意路径。 | 代码转换工具CLI入口，基于规则进行代码替换 |
| `main@tools/load_ms_weights_to_pt/transfer.py` | cmdline | untrusted_local | CLI工具入口，接收mindspeed_llm_path参数，用于将权重转换工具复制到目标目录。本地用户可以控制此参数。 | 权重加载工具CLI入口，复制checkpointing.py和serialization.py到目标目录 |
| `main@tools/convert/patch_merge/modules/merge.py` | cmdline | untrusted_local | Patch合并工具CLI入口，接收root-dir和json-file参数。本地用户可以控制路径和JSON文件内容，可能触发不安全的代码操作。 | Patch合并工具CLI入口，将patch JSON合并到源代码 |
| `load_ms_weights@tools/load_ms_weights_to_pt/serialization.py` | file | untrusted_local | 权重加载函数，接收文件路径参数f，使用pickle进行反序列化。如果用户传入恶意构造的.pt文件，可能导致任意代码执行。 | 权重加载函数，从.pt文件加载MindSpore权重 |
| `get_data_from_feature_data@src/mindspeed_mm/mindspore/data/datasets/feature_dataset.py` | file | untrusted_local | 特征数据加载函数，使用torch.load加载用户指定的.pt文件。torch.load内部使用pickle反序列化，存在任意代码执行风险。 | 特征数据加载函数，从.pt文件加载特征数据 |
| `load_json_file@tools/convert/modules/api_transformer.py` | file | untrusted_local | JSON配置文件加载函数，从api_mapping.json读取API映射配置。如果该文件被篡改，可能导致不安全的API映射。 | JSON配置文件加载函数，读取API映射配置 |

**其他攻击面**:
- CLI Interface: tools/convert/convert.py --path_to_change参数
- CLI Interface: tools/transfer.py 多个路径参数
- CLI Interface: tools/load_ms_weights_to_pt/transfer.py --mindspeed_llm_path参数
- CLI Interface: tools/convert/patch_merge/modules/merge.py --root-dir和--json-file参数
- Pickle Deserialization: tools/load_ms_weights_to_pt/serialization.py load_ms_weights函数
- Pickle Deserialization: src/mindspeed_mm/mindspore/data/datasets/feature_dataset.py torch.load调用
- File Read: tools/convert/modules/api_transformer.py api_mapping.json配置文件

---

## 3. High 漏洞 (7)

### [VULN-003-94] Code Injection via Statement Parsing - _merged_branch_builder

**严重性**: High | **CWE**: CWE-94 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `tools/convert/patch_merge/modules/patch_func_router.py:62-72` @ `_merged_branch_builder`
**模块**: tools_patch_merge

**描述**: Attacker-controlled patch_import field from JSON is used to construct import statements parsed by libcst.parse_statement(). Module names and function names from JSON are directly embedded into import statements without sanitization.

**漏洞代码** (`tools/convert/patch_merge/modules/patch_func_router.py:62-72`)

```c
patch_import_module = ".".join(patch_import.split(".")[:-1])
new_import = cst.parse_statement(f"from {patch_import_module} import {patch_import_func} as {patch_call_name}")
```

**达成路径**

args.json_file -> json.load -> patch_info["patch_import"] -> cst.parse_statement(f"from {patch_import_module} import...") [SINK: code_injection]

**验证说明**: JSON-controlled patch_import field used to construct import statements parsed by libcst.parse_statement(). Format constrained to import statement structure, but module path and function name fully attacker-controlled.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-007-94] Code Injection via Factory Class - _merged_branch_builder

**严重性**: High | **CWE**: CWE-94 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `tools/convert/patch_merge/modules/patch_class_add_factory.py:85-96` @ `_merged_branch_builder`
**模块**: tools_patch_merge

**描述**: In patch_class_add_factory.py, attacker-controlled patch_import and condition fields are used to construct import statements and condition expressions parsed by libcst.parse_statement() and cst.parse_expression().

**漏洞代码** (`tools/convert/patch_merge/modules/patch_class_add_factory.py:85-96`)

```c
patch_import_module = ".".join(patch_import.split(".")[:-1])
new_import = cst.parse_statement(f"from {patch_import_module} import {patch_import_func} as {patch_call_name}")
test=cst.parse_expression(condition)
```

**达成路径**

args.json_file -> raw_patches -> patch_info -> cst.parse_statement/import_expression [SINK: code_injection]

**验证说明**: Same pattern as VULN-003-94 in patch_class_add_factory.py. patch_import and condition fields used to construct import statements and expressions parsed by libcst.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-008-94] Code Injection via Wrapper - _build_inner_wrapped_call

**严重性**: High | **CWE**: CWE-94 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `tools/convert/patch_merge/modules/patch_wrapper_router.py:130-144` @ `_build_inner_wrapped_call`
**模块**: tools_patch_merge

**描述**: In patch_wrapper_router.py, attacker-controlled patch_import and condition fields from JSON are directly embedded into dynamically parsed code statements and expressions.

**漏洞代码** (`tools/convert/patch_merge/modules/patch_wrapper_router.py:130-144`)

```c
wrapper_name = self._merged_name_builder(self.func_name, patch)
new_import = cst.parse_statement(f"from {patch_import_module} import {wrapper_origin_name} as {wrapper_name}")
test=cst.parse_expression(condition)
```

**达成路径**

args.json_file -> raw_patches -> patch_info -> cst.parse_statement/import_expression [SINK: code_injection]

**验证说明**: Same pattern as VULN-003-94 in patch_wrapper_router.py. patch_import and condition fields directly embedded into parsed code statements.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [tools_load_weights-CWE502-indirect-pickle-001] Indirect Pickle Deserialization - load_wrapper

**严重性**: High | **CWE**: CWE-502 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `tools/load_ms_weights_to_pt/checkpointing.py:3-11` @ `load_wrapper`
**模块**: tools_load_weights
**跨模块**: tools_load_weights → mindspeed_mm.feature_dataset

**描述**: Indirect pickle deserialization via load_wrapper decorator. The load_wrapper function wraps torch.load and falls back to load_ms_weights when the original call fails. This means any code using torch.load could trigger pickle deserialization with untrusted data if the wrapped function is called with a malicious file.

**漏洞代码** (`tools/load_ms_weights_to_pt/checkpointing.py:3-11`)

```c
def load_wrapper(fn):\n    @wraps(fn)\n    def wrapper(*args, **kwargs):\n        try:\n            res = fn(*args, **kwargs)\n        except:\n            from tools.load_ms_weights_to_pt.serialization import load_ms_weights\n            res = load_ms_weights(*args, **kwargs)\n        return res\n    return wrapper
```

**达成路径**

torch.load args -> load_wrapper@checkpointing.py:3 -> load_ms_weights@serialization.py:384 -> pickle.load [SINK: pickle_deserialization]

**验证说明**: load_wrapper wraps torch.load and silently falls back to unsafe load_ms_weights on any exception. Attack requires: 1) torch.load failure, 2) attacker-controlled file path. Cross-module: patched into megatron_adaptor.py via transfer.py, affecting torch.load globally in patched environment.

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-004-94] Dynamic Import Execution - parse_path

**严重性**: High | **CWE**: CWE-94 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `tools/convert/patch_merge/modules/merge.py:186-204` @ `parse_path`
**模块**: tools_patch_merge

**描述**: JSON-controlled import paths are dynamically imported using importlib.import_module(). Attacker can specify arbitrary module paths that will be imported, potentially leading to code execution through malicious modules.

**漏洞代码** (`tools/convert/patch_merge/modules/merge.py:186-204`)

```c
for i in range(1, len(modules) + 1):
    parent_path = ".".join(modules[:i - 1])
    path = ".".join(modules[:i])
    try:
        importlib.import_module(path)
```

**达成路径**

args.json_file -> json.load -> raw_patches -> origin_import/patch_import -> importlib.import_module(path) [SINK: code_execution]

**验证说明**: importlib.import_module() called with attacker-controlled module path from JSON. Package validation (line 225) occurs AFTER import, so module code executes before validation fails. Exploitation requires malicious module to exist in environment.

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [tests-serialize-unsafe-pickle-001] Deserialization - _load

**严重性**: High | **CWE**: CWE-502 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-Core-MS/tools/load_ms_weights_to_pt/serialization.py:508-527` @ `_load`
**模块**: tests
**跨模块**: tests,tools/load_ms_weights_to_pt

**描述**: Unsafe pickle deserialization in UnpicklerWrapper.load() allows arbitrary code execution. The serialization.py module implements a custom UnpicklerWrapper that attempts to restrict find_class() but still allows arbitrary function calls through super().find_class() and get_func_by_name().

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-Core-MS/tools/load_ms_weights_to_pt/serialization.py:508-527`)

```c
unpickler = UnpicklerWrapper(data_file, **pickle_load_args)\nunpickler.persistent_load = persistent_load\nresult = unpickler.load()
```

**达成路径**

File path input [test_serialization.py:767-780] -> load_ms_weights(f) [serialization.py:384] -> _open_file_like(f, rb) [serialization.py:405] -> _load(opened_zipfile) [serialization.py:414] -> UnpicklerWrapper(data_file) [serialization.py:525] -> unpickler.load() [serialization.py:527] -> ARBITRARY_CODE_EXECUTION

**验证说明**: UnpicklerWrapper.find_class() has limited allowlist for torch modules but falls back to super().find_class() for all other modules, allowing arbitrary class instantiation. The tool is designed to patch torch.load() in downstream projects (MindSpeed-LLM), creating a real attack surface when loading untrusted .pt files. Within this repo, only test code calls it, but the intended use case is patching production torch.load().

**评分明细**: base: 30 | reachability: 25 | controllability: 25 | mitigations: -15 | context: 0 | cross_file: 0

---

### [tests-checkpointing-unsafe-import-004] Unsafe Dynamic Import - load_wrapper

**严重性**: High | **CWE**: CWE-94 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-Core-MS/tools/load_ms_weights_to_pt/checkpointing.py:1-12` @ `load_wrapper`
**模块**: tests
**跨模块**: tests,tools/load_ms_weights_to_pt

**描述**: Unsafe dynamic import in load_wrapper exception handler. The checkpointing.py load_wrapper decorator catches all exceptions and imports serialization module dynamically, then calls load_ms_weights which performs unsafe pickle deserialization.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-Core-MS/tools/load_ms_weights_to_pt/checkpointing.py:1-12`)

```c
try:\n    res = fn(*args, **kwargs)\nexcept:\n    from tools.load_ms_weights_to_pt.serialization import load_ms_weights\n    res = load_ms_weights(*args, **kwargs)
```

**达成路径**

Function call fn(*args) -> Exception raised -> Dynamic import load_ms_weights -> load_ms_weights(*args, **kwargs) -> PICKLE_DESERIALIZATION

**验证说明**: load_wrapper is designed to patch torch.load() in downstream MindSpeed-LLM projects. If original torch.load fails, it falls back to load_ms_weights which uses vulnerable UnpicklerWrapper. This is a secondary path to the pickle deserialization vulnerability (duplicate of tests-serialize-unsafe-pickle-001). The decorator enables the attack surface in patched environments.

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (2)

### [tools_load_weights-CWE22-path-traversal-001] Path Traversal - copy_weights_transfer_tool_file

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `tools/load_ms_weights_to_pt/transfer.py:16-29` @ `copy_weights_transfer_tool_file`
**模块**: tools_load_weights

**描述**: Arbitrary file copy via unsanitized path in copy_weights_transfer_tool_file(). The function uses shutil.copy() with user-controlled mindspeed_llm_path without path validation, potentially allowing files to be copied to arbitrary locations if the path contains traversal sequences.

**漏洞代码** (`tools/load_ms_weights_to_pt/transfer.py:16-29`)

```c
def copy_weights_transfer_tool_file(mindspeed_llm_path):\n    ...\n    target_directory = os.path.join(mindspeed_llm_path, "mindspeed_llm/mindspore/training/")\n    shutil.copy(checkpointing_file, target_directory)
```

**达成路径**

args.mindspeed_llm_path@transfer.py:53 -> transfer_load@transfer.py:11 -> copy_weights_transfer_tool_file@transfer.py:16 -> shutil.copy@transfer.py:28 [SINK: file_copy]

**验证说明**: CLI migration tool with user-controlled mindspeed_llm_path. Path traversal allows writing fixed files (checkpointing.py, serialization.py) to arbitrary locations. Impact limited: content is fixed, only destination controllable. Existence checks (lines 20-27) provide minimal mitigation but no path sanitization.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [tools_load_weights-CWE73-file-write-001] Arbitrary File Write - patch_torch_load

**严重性**: Medium | **CWE**: CWE-73 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `tools/load_ms_weights_to_pt/transfer.py:32-48` @ `patch_torch_load`
**模块**: tools_load_weights

**描述**: Arbitrary file modification via patch_torch_load(). The function reads and modifies Python source files at user-controlled paths without validation. An attacker could potentially modify arbitrary Python files by providing a crafted mindspeed_llm_path.

**漏洞代码** (`tools/load_ms_weights_to_pt/transfer.py:32-48`)

```c
def patch_torch_load(mindspeed_llm_path):\n    patch_file_path = os.path.join(mindspeed_llm_path, "mindspeed_llm/tasks/megatron_adaptor.py")\n    with open(patch_file_path, "r", encoding="UTF-8") as file:\n        data = file.read()\n    ...\n    with open(patch_file_path, "w", encoding="UTF-8") as file:\n        file.write(data)
```

**达成路径**

args.mindspeed_llm_path@transfer.py:53 -> transfer_load@transfer.py:11 -> patch_torch_load@transfer.py:32 -> open@transfer.py:36,48 [SINK: file_read, file_write]

**验证说明**: CLI migration tool. Path traversal allows targeting arbitrary files containing specific pattern (patch_texts). Modification is constrained to adding predefined lines. Impact limited: pattern must exist in target file, modification content is fixed. Existence and pattern checks provide partial validation.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| tests | 0 | 2 | 0 | 0 | 2 |
| tools_load_weights | 0 | 1 | 2 | 0 | 3 |
| tools_patch_merge | 0 | 4 | 0 | 0 | 4 |
| tools_transfer | 0 | 0 | 0 | 0 | 0 |
| **合计** | **0** | **7** | **2** | **0** | **9** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-94 | 5 | 50.0% |
| CWE-502 | 2 | 20.0% |
| CWE-22 | 2 | 20.0% |
| CWE-73 | 1 | 10.0% |
